/**
 * The HTTP surface.
 *
 * Rule 4 of docs/ecosystem/03 §2: `/livez`, `/readyz` and `/metrics` on every service, or it does
 * not pass CI.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **AN OPERATOR ACTS AS THEMSELVES. THERE IS NO ROUTE HERE THAT ACTS FOR SOMEBODY ELSE.**
 *
 * No route on this service takes a `userId` and performs an action as that user. The frozen
 * estate's `/internal/*` routes did — they are an act-as-anyone primitive, and
 * `deploy/gateway/dynamic/policy.yml` refuses them from outside for precisely that reason. Nothing
 * here is an equivalent:
 *
 *   - Every mutating route derives its actor from the verified bearer token. `actor` is never a
 *     body field, never a query parameter, and never a header.
 *   - A user is only ever a SUBJECT (`subjectKind: 'user'`), never a costume. Where an approval
 *     names a user, what is being authorised is an action on a thing that user owns — an
 *     entitlement, a ledger entry — performed by the operator, recorded as the operator.
 *   - A SERVICE token cannot request, approve or execute anything. It can read (`admin:read`), and
 *     that is now the entire service vocabulary. Approval is consent given by a person, and a
 *     service is not a person; a service token that could approve would make the four-eyes control
 *     satisfiable by two credentials on one machine.
 *
 * **`POST /v1/events` IS SIGNATURE-CHECKED BEFORE IT IS PARSED, AND READS NO BEARER.** It is the
 * intake for the whole estate's audit mirror (17 §2). An unsigned intake there is a forgery
 * endpoint: anyone who can reach the port could write a row into the record a dispute is settled
 * against, naming any operator for any action. The body is verified with `contracts-events`'
 * `verifyDelivery` against `OUTBOX_SIGNING_SECRET`, over the exact bytes received, BEFORE
 * `JSON.parse` is called on it.
 *
 * It used to demand `admin:audit:write` as well. No outbox relay in this estate can present a
 * bearer, and this service was additionally verifying a signature format nobody sends, so the
 * mirror received nothing at all — the route below carries the full argument, what was given up,
 * and what would restore it.
 *
 * **EVERY MUTATING ROUTE IS IDEMPOTENT.** `routeidempotency.test.ts` enumerates them from this
 * file's source and fails on one that neither wraps `withIdempotentRoute` nor states why it need
 * not. `micro-market` gained that guard after two routes were found with none, and both of them
 * created a durable artefact on every retry.
 *
 * **THE SCOPE MATCHER IS EXACT, DELIBERATELY** — the §3.3h decision, argued in `scopes.ts`.
 * `admin:*` is refused here and accepted by a sibling that calls `hasScope`; that difference is a
 * recorded choice, pinned in both directions by `scopes.test.ts`, and neither auth package is
 * changed by this repository.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import {
  ForbiddenError,
  TokenError,
  bearerFrom,
  isAdmin,
  statusFor,
  type Principal,
} from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { READ_SCOPE, requireExactScope } from './scopes.ts'
import {
  ACTIONS,
  EXECUTORS,
  isKnownAction,
  type ExecutionContext,
} from './actions.ts'
import {
  EngagementError,
  ENGAGEMENT_SERVICES,
  ENGAGEMENT_TREASURY_SUBJECT,
  engagementSubjectOf,
  findPolicy,
  listPolicies,
  listTransfers,
  parseCapShards,
  parseShards,
  parseWei,
  RaiseNeedsApprovalError,
  readFeeRecycle,
  setFeeRecycle,
  setPolicy,
  transferTotals,
  FEE_RECYCLE_CEILING_BPS,
  SEED_PER_DAY_CEILING_WEI,
  SEED_PER_MARKET_CEILING_WEI,
  TRANSFER_CAP_CEILING_SHARDS,
} from './engagement.ts'
import {
  ApprovalError,
  ApprovalNotFoundError,
  ApprovalStateError,
  REASON_CODES,
  SelfApprovalError,
  decide,
  findApproval,
  listApprovals,
  recordExecution,
  requestApproval,
  type Approval,
  type ApprovalState,
} from './approvals.ts'
import {
  DuplicateMirrorError,
  appendAudit,
  auditToJson,
  readAudit,
  verifyChain,
} from './audit.ts'
import { BroadcastError, BroadcastNotFoundError, listBroadcasts, publishBroadcast, retractBroadcast, type Severity } from './broadcasts.ts'
import { FlagError, listFlags, setFlag } from './flags.ts'
import { composeEstate, type EstateDeps } from './estate.ts'
import {
  IdempotencyInFlightError,
  IdempotencyKeyReuseError,
  requestFingerprint,
  withIdempotency,
} from './idempotency.ts'
import { withInbox, SIGNATURE_HEADER, type Db } from './outbox.ts'
// The registry, and the one place that decides which topics the operator audit log carries.
// Read rather than restated: a decision copied into a consumer is a decision that drifts.
import { auditRowFor, isRegisteredTopic, validateEnvelope, verifyDelivery } from '@cloudsforge/contracts-events'
import { UpstreamError, type BillingClient, type IdentityClient, type LedgerClient, type MarketClient } from './upstreams.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

const MAX_BODY_BYTES = 256 * 1024
const SAFE_REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * There is no audit topic, and this constant is gone.
 *
 * It used to be `'.audit.recorded'`, and the intake keyed on that suffix. Nothing in the estate
 * ever published such a topic — the string appeared in exactly one non-test place, this
 * declaration — so **the mirror was a consumer with no producer** and this log held only this
 * service's own rows. 17 §7 claim 9 ("an operator answers where did this user's money go from
 * `admin-web` alone, by correlation id") could not pass, and an empty timeline read as an answer.
 *
 * The mirror now consumes the domain topics that already exist. `contracts-events`'s
 * `TOPIC_AUDIT` decides, per topic, whether the operator log carries it and what its key names;
 * every other column was already a required field of the envelope. The argument for reading the
 * bus rather than adding a parallel stream — that a second stream written by a second call site
 * can disagree with the domain event it accompanies, and an audit log that can disagree with the
 * system it audits is worse than none — is in that package's `audit.ts` header.
 */

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  readonly sql: Db
  readonly producer: string
  readonly ledger: LedgerClient
  readonly market: MarketClient
  readonly billing: BillingClient
  /** Only `identity.role.grant` uses it, and it is the only call that presents the service token
   *  because identity's role gate refuses an operator bearer outright. See `upstreams.ts`. */
  readonly identity: IdentityClient
  readonly readiness: EstateDeps['readiness']
  /**
   * The secrets `POST /v1/events` will accept, newest first — a list so that rotating the estate's
   * shared signing secret has an overlap window, rather than requiring every producer to change in
   * the same instant this service does. `verifyDelivery` takes the candidates natively and reports
   * which one matched; this service never loops, so the timing-safe comparison stays in the
   * contract.
   */
  readonly eventAcceptSecrets: readonly string[]
  readonly approvalTtlMinutes: number
  readonly now?: () => Date
  readonly beforeScrape?: () => Promise<void>
}

/** Domain metrics, declared rather than inferred from a log line — AD-20. */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'admin_operator_actions_total',
      help: 'Operator actions, by action and outcome. 13 §283 alerts on this per operator.',
      kind: 'counter',
      labels: ['action', 'outcome'],
    })
    .register({
      name: 'admin_approvals_total',
      help: 'Approval requests, by action and terminal state.',
      kind: 'counter',
      labels: ['action', 'state'],
    })
    .register({
      name: 'admin_approvals_expired_total',
      help: 'Approval requests that no second operator answered before the deadline.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'admin_self_approvals_refused_total',
      help: 'Attempts by a requester to decide their own request. Never expected to be non-zero.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'admin_audit_events_total',
      help: 'Audit rows appended, by source and outcome.',
      kind: 'counter',
      labels: ['source', 'outcome'],
    })
    .register({
      name: 'admin_audit_mirror_rejected_total',
      help: 'Inbound audit mirror rows refused, by reason.',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'admin_audit_chain_length',
      help: 'Rows in the audit chain.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'admin_audit_chain_breaks',
      help: 'Breaks found by the last verification pass. SD-16: non-zero is a P0.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'admin_audit_chain_verified_seq',
      help: 'The highest sequence a clean verification has reached.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'admin_estate_tile_status_total',
      help: 'Estate view tiles by status. Alert here, not on the HTTP error rate.',
      kind: 'counter',
      labels: ['tile', 'status'],
    })
}

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
  readonly headers?: Record<string, string>
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
}

interface Route {
  readonly method: string
  /** Used verbatim as the metric label, so cardinality is bounded by the number of routes. */
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

/**
 * Compile `/v1/approvals/:id` into a matcher. The segment pattern excludes `/` so a parameter
 * cannot swallow the rest of the path and make one route answer for another.
 */
function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':')
        ? `(?<${segment.slice(1)}>[^/]+)`
        : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

/** The action has no upstream route. See the §3.3g decision in `actions.ts`. */
class ActionUnavailableError extends Error {
  readonly action: string
  readonly reason: string
  constructor(action: string, reason: string) {
    super(`${action} cannot be executed: ${reason}`)
    this.name = 'ActionUnavailableError'
    this.action = action
    this.reason = reason
  }
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()

    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route | undefined
    let params: Record<string, string> = {}
    for (const route of routes) {
      if (route.method !== method) continue
      const match = route.pattern.exec(url.pathname)
      if (match) {
        matched = route
        params = { ...match.groups }
        break
      }
    }

    const routeLabel = matched ? matched.path : 'unmatched'
    const log = deps.logger.child({ requestId, method, route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method,
        route: routeLabel,
        status: String(status),
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, { method, route: routeLabel })
    }

    void handle(matched, { req, url, requestId, log, params }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status)
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500)
      })
  })
}

/**
 * Map every failure onto a status, grouped by what the caller should do about it.
 *
 *   * **400** — the request could not be legal. Fix it; retrying will not help.
 *   * **403** — a scope, a role, or **the four-eyes refusal**, which gets its own code so a
 *     console can say "you raised this one" rather than "forbidden".
 *   * **404** — something named does not exist.
 *   * **409** — well formed, but the state refuses it: an already-decided approval, an
 *     idempotency key reused with a different body.
 *   * **501** — the action is real, this service knows what it means, and the upstream route it
 *     needs does not exist. Distinguished from 400 on purpose: the operator did nothing wrong,
 *     and the response names the route the estate is missing.
 *   * **502** — an upstream refused an execution the operators had authorised.
 *   * **503** — an upstream is unreachable, or an idempotent request is still in flight.
 */
async function handle(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await route.handle(ctx, deps)
  } catch (err) {
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      // The reason is logged, never returned — "signature verification failed" versus "expired"
      // tells an attacker which half of a forged token to fix.
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid bearer token is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      ctx.log.info('forbidden request', { required })
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof RaiseNeedsApprovalError) {
      // 403 like the self-approval refusal, and for the same reason: the operator's authority,
      // not the request's shape, is what fell short — the console should say "raise it through
      // the queue", not "bad request".
      ctx.log.warn('an engagement raise was attempted without an approval')
      return errorReply(403, 'raise_needs_approval', err.message, ctx.requestId)
    }
    if (err instanceof SelfApprovalError) {
      deps.metrics.increment('admin_self_approvals_refused_total')
      // Logged at warn, because it is either a UI that offered a button it should not have or an
      // operator trying to route around the control. Both are worth seeing.
      ctx.log.warn('self-approval refused')
      return errorReply(403, 'self_approval_refused', err.message, ctx.requestId)
    }
    if (err instanceof ActionUnavailableError) {
      return {
        status: 501,
        body: {
          error: {
            code: 'action_has_no_upstream',
            message: err.message,
            action: err.action,
            requestId: ctx.requestId,
          },
        },
      }
    }
    if (err instanceof DuplicateMirrorError) {
      // 200, not 409. At-least-once delivery guarantees this; answering an error would make a
      // correctly-behaving producer retry for ever.
      return { status: 200, body: { status: 'duplicate', sourceEventId: err.sourceEventId } }
    }
    if (err instanceof IdempotencyKeyReuseError) {
      return errorReply(409, 'idempotency_key_reused', err.message, ctx.requestId)
    }
    if (err instanceof IdempotencyInFlightError) {
      // 503 with a retry hint, not 409. The first attempt may still succeed.
      return {
        status: 503,
        headers: { 'retry-after': '1' },
        body: { error: { code: 'in_flight', message: err.message, requestId: ctx.requestId } },
      }
    }
    if (err instanceof ApprovalNotFoundError || err instanceof BroadcastNotFoundError) {
      return errorReply(404, 'not_found', err.message, ctx.requestId)
    }
    if (err instanceof ApprovalStateError) {
      return errorReply(409, 'state_conflict', err.message, ctx.requestId)
    }
    if (err instanceof UpstreamError) {
      // 502 when the peer decided, 503 when we could not reach it. The operator's next move is
      // different: one is "the upstream said no", the other is "try again".
      ctx.log.error('an upstream failed an authorised execution', { upstream: err.upstream, status: err.status })
      return errorReply(
        err.peerDecided ? 502 : 503,
        err.peerDecided ? 'upstream_refused' : 'upstream_unavailable',
        err.message,
        ctx.requestId,
      )
    }
    if (
      err instanceof BadRequestError ||
      err instanceof ApprovalError ||
      err instanceof BroadcastError ||
      err instanceof FlagError ||
      err instanceof EngagementError ||
      err instanceof RangeError
    ) {
      return errorReply(400, 'bad_request', err.message, ctx.requestId)
    }
    if (err instanceof NotFoundError) {
      return errorReply(404, 'not_found', err.message, ctx.requestId)
    }
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/* ------------------------------------------------------------------------ authentication */

async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<Principal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  // A missing token is a token fault, so it takes the same 401 path as a bad one rather than being
  // a separate branch that can drift away from it.
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  return deps.verifier.principal(token)
}

/**
 * An OPERATOR. A human, holding `role:admin`, acting as themselves.
 *
 * A service token is refused outright and there is no scope that changes that. Approval is consent
 * given by a person; a service that could approve would make the four-eyes control satisfiable by
 * two credentials sitting on one machine, which is not two pairs of eyes.
 */
function requireOperator(principal: Principal): string {
  if (principal.kind !== 'user') {
    throw new ForbiddenError('role:admin (a service token cannot act as an operator)')
  }
  if (!isAdmin(principal)) throw new ForbiddenError('role:admin')
  return `user:${principal.userId}`
}

/** A reader: an operator, or a service holding the exact `admin:read` scope. */
function requireReader(principal: Principal): string {
  if (principal.kind === 'user') return requireOperator(principal)
  requireExactScope(principal, READ_SCOPE)
  return `service:${principal.service}`
}

/** The operator's raw bearer, forwarded to upstreams that record which administrator acted. */
function operatorBearer(ctx: RequestContext): string {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  return token
}

/* ------------------------------------------------------------------------ routes */

function buildRoutes(): Route[] {
  const define = (
    method: string,
    path: string,
    handler: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>,
  ): Route => ({ method, path, pattern: compile(path), handle: handler })

  return [
    define('GET', '/livez', async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() })),

    define('GET', '/readyz', async (_ctx, deps) => {
      const report = await deps.lifecycle.readyz()
      return { status: report.ready ? 200 : 503, body: report }
    }),

    define('GET', '/metrics', async (ctx, deps) => {
      try {
        await deps.beforeScrape?.()
      } catch (err) {
        ctx.log.warn('gauge refresh failed; serving the previous values', { err })
      }
      return {
        status: 200,
        text: deps.metrics.render(),
        contentType: 'text/plain; version=0.0.4; charset=utf-8',
      }
    }),

    /* ---------------------------------------------------------------- the audit mirror */

    /**
     * The audit mirror: the intake for the estate's audit of record.
     *
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * **MAC-ONLY. NO BEARER TOKEN IS READ HERE, AND THAT IS THE REPAIR.**
     *
     * This route had TWO independent walls, either of which alone made it undeliverable, and both
     * were measured against the running estate before being touched:
     *
     *   1. **The wrong signature scheme.** It verified `x-cloudsforge-signature: sha256=<hmac>`,
     *      a format this repository invented. Every producer sends `cf-signature:
     *      t=<s>,v1=<hmac>`. A correctly signed delivery answered `401 bad_signature`. See
     *      `outbox.ts`'s signing header for why adopting the estate scheme is strictly stronger
     *      (it has a replay window; the local one had none).
     *   2. **A bearer and an `admin:audit:write` scope no producer can present.** An outbox relay
     *      is a background job woken by a Postgres poll — no session, no user, no way to mint a
     *      token. All twenty-one relays in the estate were read, not assumed: every one sends the
     *      signature and the event id and NOTHING else. Presenting the local scheme's signature
     *      with no `Authorization` answered `401 unauthenticated`.
     *
     * So the mirror for all 26 audited topics received nothing, ever — which
     * `deploy/README.md:183` had already recorded as making 17 §7 claim 9 unpassable. **An empty
     * operator timeline during an incident looks like an answer**, and that is the worst failure
     * mode this tool has: an operator asks "where did this user's money go", sees nothing, and
     * concludes nothing happened.
     *
     * **WHAT WAS LOST, STATED PLAINLY RATHER THAN GLOSSED.** `source` used to be the
     * scope-checked principal's service name, and an envelope whose `producer` disagreed with it
     * was refused — "a service may mirror its own rows, not somebody else's". That check is gone
     * with the bearer, and `source` is now `event.producer`. The residual risk is real and worth
     * naming: any holder of the estate outbox secret can now mirror a row attributed to any
     * producer. What still stands behind it is that `validateEnvelope` requires the producer to
     * own the topic namespace, so a forged row must at least be internally consistent, and that
     * the secret is held only by services — never by a browser and never by an operator.
     *
     * **This is not a net weakening**, because the alternative was not "keep the check": the
     * check was attached to a route that refused 100% of legitimate traffic, so it protected
     * nothing that existed. A no-rows audit log is not a safer audit log. The honest fix that
     * restores the distinction is a PER-PRODUCER signing secret rather than one estate-wide
     * secret, which is a `micro-deploy` and `contracts-events` change and is reported there.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    define('POST', '/v1/events', async (ctx, deps) => {
      // ── SIGNATURE FIRST, BEFORE THE PARSE. See the file header.
      //
      // Decoded exactly ONCE, and the same string is both verified and parsed. Verifying one
      // string and parsing another is how an implementation drifts towards acting on something
      // other than what it authenticated.
      const raw = (await readRaw(ctx.req)).toString('utf8')
      const presented = headerOf(ctx.req, SIGNATURE_HEADER)
      const verification = presented
        ? verifyDelivery(raw, presented, deps.eventAcceptSecrets, {
            ...(deps.now ? { now: deps.now().getTime() } : {}),
          })
        : ({ ok: false, reason: 'malformed_header' } as const)
      if (!verification.ok) {
        deps.metrics.increment('admin_audit_mirror_rejected_total', { reason: 'bad_signature' })
        // The reason is logged, never returned: telling a prober "stale" rather than "mismatch"
        // tells them which half of a forgery to fix.
        ctx.log.warn('an inbound event failed its signature check', { reason: verification.reason })
        return errorReply(401, 'bad_signature', 'the event signature did not verify', ctx.requestId)
      }
      if (verification.keyIndex > 0) {
        // Still accepting a rotated-out secret. Not an error; a countdown.
        ctx.log.warn('an event was signed with a superseded secret', { keyIndex: verification.keyIndex })
      }

      let envelope: Record<string, unknown>
      try {
        const parsed: unknown = JSON.parse(raw)
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new BadRequestError('an event envelope must be a JSON object')
        }
        envelope = parsed as Record<string, unknown>
      } catch {
        deps.metrics.increment('admin_audit_mirror_rejected_total', { reason: 'malformed' })
        throw new BadRequestError('the event body is not valid JSON')
      }

      const topic = typeof envelope['topic'] === 'string' ? envelope['topic'] : ''
      const eventId = typeof envelope['id'] === 'string' ? envelope['id'] : ''
      if (!UUID.test(eventId)) {
        deps.metrics.increment('admin_audit_mirror_rejected_total', { reason: 'malformed' })
        throw new BadRequestError('an event envelope must carry a uuid id')
      }

      // A topic this build's copy of the registry does not know. Accepted and ignored, because the
      // honest reading is that THIS service is behind its producer — `contracts-events` is
      // additive-only, so a topic it lacks is one added after this build. Answering 4xx would make
      // a correctly-behaving relay retry for ever over something harmless.
      if (!isRegisteredTopic(topic)) {
        deps.metrics.increment('admin_audit_mirror_rejected_total', { reason: 'unhandled_topic' })
        return { status: 202, body: { status: 'ignored', topic } }
      }

      // Everything the audit row needs is a field of the envelope, and every one of them is
      // REQUIRED here — actor, correlationId, occurredAt, the producer owning its own topic
      // namespace. That is why there is no `*.audit.recorded` stream: see the header of
      // `contracts/packages/events/src/audit.ts` for the argument, which is that a second stream
      // written by a second call site can disagree with the domain event it accompanies.
      const validated = validateEnvelope(envelope)
      if (!validated.ok) {
        deps.metrics.increment('admin_audit_mirror_rejected_total', { reason: 'malformed' })
        throw new BadRequestError(validated.errors.join('; '))
      }
      const event = validated.value

      // ── THE SOURCE IS THE ENVELOPE'S PRODUCER, AND WHY THAT IS NOW THE BEST AVAILABLE FACT.
      //
      // It was the scope-checked principal's service name, cross-checked against `event.producer`.
      // With the bearer gone — see the route header for why it had to go — there is no second,
      // independent statement of who is on the connection, so the cross-check would compare
      // `event.producer` with itself. A guard that compares a value to a copy of itself is exactly
      // the kind of check this estate keeps producing and that cannot fail, so it is DELETED
      // rather than left standing as reassurance.
      //
      // `validateEnvelope` above is what still constrains this: it requires the producer to own
      // the topic namespace, so `producer: "ledger"` cannot carry an `identity.*` topic.
      const sender = event.producer

      const mirrored = auditRowFor(event)
      if (!mirrored) {
        // A registered topic the operator audit log deliberately does not carry — a battle
        // resolving, a vote being cast. `TOPIC_AUDIT` records why for every one of them.
        deps.metrics.increment('admin_audit_mirror_rejected_total', { reason: 'unaudited_topic' })
        return { status: 202, body: { status: 'ignored', topic } }
      }

      const outcome = await withInbox(deps.sql, topic, eventId, async (tx) =>
        appendAudit(
          tx,
          {
            actor: mirrored.actor,
            action: mirrored.action,
            subjectKind: mirrored.subjectKind,
            subjectId: mirrored.subjectId,
            outcome: mirrored.outcome,
            correlationId: mirrored.correlationId,
            payload: mirrored.payload,
            source: sender,
            sourceEventId: mirrored.sourceEventId,
            occurredAt: new Date(mirrored.occurredAt),
          },
          deps.now,
        ),
      )
      if (outcome.status === 'duplicate') {
        return { status: 200, body: { status: 'duplicate', eventId } }
      }
      deps.metrics.increment('admin_audit_events_total', {
        source: sender,
        outcome: mirrored.outcome,
      })
      return { status: 201, body: { status: 'recorded', seq: outcome.value.seq.toString(), hash: outcome.value.hash } }
    }),

    /* ---------------------------------------------------------------- audit reads */

    define('GET', '/v1/audit', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const reader = requireReader(principal)
      const params = ctx.url.searchParams
      const before = params.get('before')
      const page = await readAudit(deps.sql, {
        ...(params.get('actor') ? { actor: params.get('actor')! } : {}),
        ...(params.get('action') ? { action: params.get('action')! } : {}),
        ...(params.get('subjectKind') ? { subjectKind: params.get('subjectKind')! } : {}),
        ...(params.get('subjectId') ? { subjectId: params.get('subjectId')! } : {}),
        ...(params.get('correlationId') ? { correlationId: params.get('correlationId')! } : {}),
        ...(params.get('source') ? { source: params.get('source')! } : {}),
        ...(before ? { before: parseCursor(before) } : {}),
        limit: parseLimit(params.get('limit')),
      })
      ctx.log.info('audit read', { reader, count: page.events.length })
      return {
        status: 200,
        body: { events: page.events.map(auditToJson), nextCursor: page.nextCursor },
      }
    }),

    define('GET', '/v1/audit/verify', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      // `from=0` re-walks the whole chain rather than resuming from the checkpoint. That is the
      // thing an operator investigating a suspected tamper needs, and the reason it is a parameter
      // rather than the default is cost: the nightly job resumes, a human asks for everything.
      const from = ctx.url.searchParams.get('from')
      const result = await verifyChain(deps.sql, {
        ...(from !== null ? { from: parseCursor(from) } : {}),
        limit: parseLimit(ctx.url.searchParams.get('limit'), 10_000, 200_000),
      })
      deps.metrics.set('admin_audit_chain_breaks', result.breaks.length)
      // 200 either way. The caller asked whether the chain verifies and this is the answer; a 500
      // would deny a monitoring system the fact it exists to read. The `ok` field is the signal.
      return {
        status: 200,
        body: {
          ok: result.ok,
          checked: result.checked,
          from: result.from.toString(),
          to: result.to.toString(),
          totalEvents: result.totalEvents,
          headHash: result.headHash,
          breaks: result.breaks.map((b) => ({ kind: b.kind, seq: b.seq.toString(), detail: b.detail })),
        },
      }
    }),

    /* ---------------------------------------------------------------- the approval queue */

    define('GET', '/v1/actions', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      // The catalogue, including the blocked entry and the reason. An operator console renders the
      // 501 before the operator hits it, and the reason is the same string the 501 carries.
      return {
        status: 200,
        body: {
          actions: Object.entries(ACTIONS).map(([name, spec]) => ({ name, ...spec })),
          reasonCodes: REASON_CODES,
        },
      }
    }),

    define('GET', '/v1/approvals', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      const params = ctx.url.searchParams
      const state = params.get('state')
      const approvals = await listApprovals(deps.sql, {
        ...(state ? { state: parseState(state) } : {}),
        ...(params.get('action') ? { action: params.get('action')! } : {}),
        ...(params.get('requestedBy') ? { requestedBy: params.get('requestedBy')! } : {}),
        limit: parseLimit(params.get('limit')),
      })
      return { status: 200, body: { approvals } }
    }),

    define('GET', '/v1/approvals/:id', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      const approval = await findApproval(deps.sql, itemIdOf(ctx))
      if (!approval) throw new NotFoundError(`no approval request ${ctx.params['id']}`)
      return { status: 200, body: { approval } }
    }),

    define('POST', '/v1/approvals', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)

      const action = requireString(body, 'action')
      if (!isKnownAction(action)) {
        throw new BadRequestError(
          `action must be one of ${Object.keys(ACTIONS).join(', ')} (got ${action})`,
        )
      }
      const spec = ACTIONS[action]!
      // ── THE §3.3g REFUSAL. A queue that accepts work it cannot execute lies to the operator
      // waiting on it, and leaves an approved row that reads as two operators having authorised
      // something that never happened. See the header of `actions.ts`.
      if (spec.route === null) {
        throw new ActionUnavailableError(action, spec.blockedReason ?? 'no upstream route exists')
      }
      // ── A READ DOES NOT SPEND SIGNATURES. 21 §6's approval column reads "none (read)" for
      // engagement.report; the queue refuses it and names the GET, the same shape as the 501
      // naming the missing route.
      if (spec.approval === 'read') {
        throw new BadRequestError(
          `${action} is a read and needs no approval — call ${spec.route.split(' — ')[0]} instead`,
        )
      }

      const subjectId = requireString(body, 'subjectId')
      const params = (body['params'] ?? {}) as Record<string, unknown>
      if (typeof params !== 'object' || params === null || Array.isArray(params)) {
        throw new BadRequestError('params must be a JSON object')
      }
      for (const name of spec.requiredParams) {
        if (typeof params[name] !== 'string' && typeof params[name] !== 'boolean') {
          throw new BadRequestError(`params.${name} is required for ${action}`)
        }
      }
      // ── The engagement actions are validated at REQUEST time as well as at execution: a cap
      // breach discovered after two operators have signed wastes both signatures, and 21 §8 says
      // nothing may move before the caps exist — so a transfer naming a service with no policy
      // row is refused before it ever becomes a pending row someone could approve. The schema
      // trigger (engagement_transfers_within_cap) remains the enforcement of record.
      if (action === 'engagement.transfer') {
        const service = String(params['service'])
        if (!ENGAGEMENT_SERVICES.includes(service)) {
          throw new BadRequestError(`params.service must be one of ${ENGAGEMENT_SERVICES.join(', ')}`)
        }
        const amount = parseShards(String(params['amountShards']))
        const policy = await findPolicy(deps.sql, service)
        if (!policy) {
          throw new BadRequestError(
            `no engagement policy exists for ${service} — the caps must exist before a Shard moves (21 §8); ` +
              'raise one through engagement.policy.set first',
          )
        }
        if (amount > BigInt(policy.transferCapShards)) {
          throw new BadRequestError(
            `a transfer of ${amount} Shards exceeds engagement:${service}'s policy cap of ${policy.transferCapShards}`,
          )
        }
      }
      if (action === 'engagement.policy.set') {
        const service = String(params['service'])
        if (service !== 'platform' && !ENGAGEMENT_SERVICES.includes(service)) {
          throw new BadRequestError(
            `params.service must be 'platform' (the fee recycle) or one of ${ENGAGEMENT_SERVICES.join(', ')}`,
          )
        }
        // Shape checks only — the ceilings and the raise/lower asymmetry live in engagement.ts
        // and the schema, and the executor goes through both.
        if (typeof params['transferCapShards'] === 'string') parseCapShards(params['transferCapShards'])
        if (typeof params['seedPerMarketWei'] === 'string') parseWei(params['seedPerMarketWei'])
        if (typeof params['seedPerDayWei'] === 'string') parseWei(params['seedPerDayWei'])
        if (service === 'platform' && typeof params['recycleBps'] !== 'string') {
          throw new BadRequestError('params.recycleBps is required to set the fee recycle')
        }
      }

      return withIdempotentRoute(ctx, '/v1/approvals', async () => {
        const outcome = await withIdempotency(deps.sql, {
          principal: operator,
          route: '/v1/approvals',
          clientKey: idempotencyKeyOf(ctx),
          requestHash: requestFingerprint(body),
          run: async (tx) => {
            const { approval } = await requestApproval(
              tx,
              {
                action,
                subjectKind: spec.subjectKind,
                subjectId,
                params,
                reasonCode: requireString(body, 'reasonCode'),
                reason: requireString(body, 'reason'),
                requestedBy: operator,
                ttlMinutes: deps.approvalTtlMinutes,
                correlationId: ctx.requestId,
              },
              deps.now,
            )
            return { response: { approval }, artefactId: approval.id }
          },
        })
        deps.metrics.increment('admin_approvals_total', { action, state: 'pending' })
        deps.metrics.increment('admin_operator_actions_total', {
          action: 'approval.requested',
          outcome: 'allowed',
        })
        return { status: outcome.replayed ? 200 : 201, body: outcome.result }
      })
    }),

    define('POST', '/v1/approvals/:id/decision', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const bearer = operatorBearer(ctx)
      const body = await readJson(ctx.req)
      const grant = body['grant']
      if (typeof grant !== 'boolean') throw new BadRequestError('grant must be true or false')
      const id = itemIdOf(ctx)

      return withIdempotentRoute(ctx, '/v1/approvals/:id/decision', async () => {
        const outcome = await withIdempotency(deps.sql, {
          principal: operator,
          route: '/v1/approvals/:id/decision',
          clientKey: idempotencyKeyOf(ctx),
          requestHash: requestFingerprint({ id, ...body }),
          run: async (tx) => {
            const { approval } = await decide(
              tx,
              {
                id,
                operator,
                grant,
                note: typeof body['note'] === 'string' ? body['note'] : null,
                correlationId: ctx.requestId,
              },
              deps.now,
            )
            return { response: { approval }, artefactId: approval.id }
          },
        })
        const approval = outcome.result.approval
        deps.metrics.increment('admin_approvals_total', {
          action: approval.action,
          state: approval.state,
        })
        deps.metrics.increment('admin_operator_actions_total', {
          action: grant ? 'approval.granted' : 'approval.rejected',
          outcome: 'allowed',
        })

        if (!grant || outcome.replayed) {
          return { status: outcome.replayed ? 200 : 201, body: { approval, execution: null } }
        }

        // ══════════════════════════════════════════════════════════════════════════════════
        // EXECUTION IS A SEPARATE TRANSACTION, DELIBERATELY, AND IT IS NOT ROLLED BACK ON
        // FAILURE.
        //
        // The upstream call cannot be inside the decision's transaction: an HTTP request is not
        // transactional, and holding a database transaction open across one is how a slow peer
        // exhausts a connection pool. So the decision commits, and then the action runs.
        //
        // A failed execution therefore leaves an APPROVED, UNEXECUTED row — which is the honest
        // state and the one an operator can act on. Rolling the approval back would erase the
        // record that two operators agreed, and retrying would then need a third signature for
        // something already authorised twice. `recordExecution` is at-most-once, and every
        // executor is idempotent at its upstream, so a retry is safe.
        // ══════════════════════════════════════════════════════════════════════════════════
        const execution = await execute(deps, approval, operator, bearer, ctx)
        return { status: 201, body: { approval: execution.approval, execution: execution.detail } }
      })
    }),

    /* ---------------------------------------------------------------- flags */

    define('GET', '/v1/flags', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      return { status: 200, body: { flags: await listFlags(deps.sql) } }
    }),

    define('PUT', '/v1/flags/:key', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)
      const enabled = body['enabled']
      if (typeof enabled !== 'boolean') throw new BadRequestError('enabled must be true or false')

      const result = await deps.sql.begin(async (tx) => ({
        value: await setFlag(
          tx,
          {
            key: ctx.params['key'] ?? '',
            enabled,
            description: requireString(body, 'description'),
            owner: requireString(body, 'owner'),
            operator,
            correlationId: ctx.requestId,
          },
          deps.producer,
          deps.now,
        ),
      }))
      deps.metrics.increment('admin_operator_actions_total', {
        action: 'flag.changed',
        outcome: 'allowed',
      })
      return { status: 200, body: { flag: result.value.flag, changed: result.value.changed } }
    }),

    /* ---------------------------------------------------------------- broadcasts */

    define('GET', '/v1/broadcasts', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      const live = ctx.url.searchParams.get('live') === 'true'
      const now = (deps.now ?? (() => new Date()))()
      return {
        status: 200,
        body: {
          broadcasts: await listBroadcasts(deps.sql, {
            ...(live ? { liveAt: now } : {}),
            limit: parseLimit(ctx.url.searchParams.get('limit')),
          }),
        },
      }
    }),

    define('POST', '/v1/broadcasts', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)

      return withIdempotentRoute(ctx, '/v1/broadcasts', async () => {
        const outcome = await withIdempotency(deps.sql, {
          principal: operator,
          route: '/v1/broadcasts',
          clientKey: idempotencyKeyOf(ctx),
          requestHash: requestFingerprint(body),
          run: async (tx) => {
            const { broadcast } = await publishBroadcast(
              tx,
              {
                severity: requireString(body, 'severity') as Severity,
                title: requireString(body, 'title'),
                body: requireString(body, 'body'),
                ...(typeof body['startsAt'] === 'string' ? { startsAt: parseDate(body['startsAt'], 'startsAt') } : {}),
                ...(typeof body['endsAt'] === 'string' ? { endsAt: parseDate(body['endsAt'], 'endsAt') } : {}),
                operator,
                correlationId: ctx.requestId,
              },
              deps.producer,
              deps.now,
            )
            return { response: { broadcast }, artefactId: broadcast.id }
          },
        })
        deps.metrics.increment('admin_operator_actions_total', {
          action: 'broadcast.published',
          outcome: 'allowed',
        })
        return { status: outcome.replayed ? 200 : 201, body: outcome.result }
      })
    }),

    define('DELETE', '/v1/broadcasts/:id', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const result = await deps.sql.begin(async (tx) => ({
        value: await retractBroadcast(tx, itemIdOf(ctx), operator, ctx.requestId, deps.producer, deps.now),
      }))
      deps.metrics.increment('admin_operator_actions_total', {
        action: 'broadcast.retracted',
        outcome: 'allowed',
      })
      return { status: 200, body: { broadcast: result.value.broadcast } }
    }),

    /* ---------------------------------------------------------------- the engagement treasury */

    define('GET', '/v1/engagement/policies', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      return {
        status: 200,
        body: {
          policies: await listPolicies(deps.sql),
          feeRecycle: await readFeeRecycle(deps.sql),
          // The schema ceilings, served so a console can render the bounds an operator is
          // choosing inside — the same numbers migrations.ts version 8 CHECKs.
          ceilings: {
            transferCapShards: TRANSFER_CAP_CEILING_SHARDS.toString(),
            seedPerMarketWei: SEED_PER_MARKET_CEILING_WEI.toString(),
            seedPerDayWei: SEED_PER_DAY_CEILING_WEI.toString(),
            feeRecycleBps: FEE_RECYCLE_CEILING_BPS,
          },
        },
      }
    }),

    /**
     * The LOWERING lane — one operator, no queue. The devplatform asymmetry
     * (devplatform/src/server.ts:981): lowering a cap narrows what can move and is the operator
     * doing the platform's work for it; raising is the abuse, goes through `engagement.policy.set`
     * with two operators, and is refused here AND by the `engagement_raise_needs_approval`
     * trigger for any writer that skips this route. `:service` may be 'platform', which addresses
     * the fee-recycle percentage.
     */
    define('PUT', '/v1/engagement/policies/:service', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)
      const service = ctx.params['service'] ?? ''

      if (service === 'platform') {
        const bps = requireString(body, 'recycleBps')
        if (!/^\d{1,4}$/.test(bps)) throw new BadRequestError('recycleBps must be a decimal string of basis points')
        const result = await deps.sql.begin(async (tx) => ({
          value: await setFeeRecycle(
            tx,
            { recycleBps: Number(bps), operator, approvalId: null, correlationId: ctx.requestId },
            deps.now,
          ),
        }))
        deps.metrics.increment('admin_operator_actions_total', {
          action: 'engagement.policy.lowered',
          outcome: 'allowed',
        })
        return { status: 200, body: { feeRecycle: result.value } }
      }

      const change = {
        ...(typeof body['transferCapShards'] === 'string'
          ? { transferCapShards: parseCapShards(body['transferCapShards']) }
          : {}),
        ...(typeof body['seedPerMarketWei'] === 'string'
          ? { seedPerMarketWei: parseWei(body['seedPerMarketWei']) }
          : {}),
        ...(typeof body['seedPerDayWei'] === 'string'
          ? { seedPerDayWei: parseWei(body['seedPerDayWei']) }
          : {}),
        ...(body['seedPerMarketWei'] === null ? { seedPerMarketWei: null } : {}),
        ...(body['seedPerDayWei'] === null ? { seedPerDayWei: null } : {}),
      }
      if (Object.keys(change).length === 0) {
        throw new BadRequestError(
          'nothing to change — send transferCapShards, or seedPerMarketWei and seedPerDayWei (null clears the pair)',
        )
      }
      const result = await deps.sql.begin(async (tx) => ({
        value: await setPolicy(
          tx,
          { service, change, operator, approvalId: null, correlationId: ctx.requestId },
          deps.now,
        ),
      }))
      deps.metrics.increment('admin_operator_actions_total', {
        action: 'engagement.policy.lowered',
        outcome: 'allowed',
      })
      return { status: 200, body: { policy: result.value } }
    }),

    /**
     * 21 §6's third action: balances and spend, read straight off the ledger — the executor-less
     * shape the queue refuses, served here to anyone `requireReader` admits. The balances come
     * from the ledger because the ledger is the truth (21 §4: "an auditor reconstructs the entire
     * programme from the ledger alone"); the transfer rows are this service's record of WHO was
     * authorised to cause them.
     */
    define('GET', '/v1/engagement/report', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const reader = requireReader(principal)
      const policies = await listPolicies(deps.sql)
      const treasury = await deps.ledger.balancesForSubject(ENGAGEMENT_TREASURY_SUBJECT)
      const services = []
      for (const policy of policies) {
        services.push({
          service: policy.service,
          subject: engagementSubjectOf(policy.service),
          balances: await deps.ledger.balancesForSubject(engagementSubjectOf(policy.service)),
        })
      }
      ctx.log.info('engagement report read', { reader, services: services.length })
      return {
        status: 200,
        body: {
          treasury: { subject: ENGAGEMENT_TREASURY_SUBJECT, balances: treasury },
          services,
          spendShardsByService: await transferTotals(deps.sql),
          transfers: await listTransfers(deps.sql),
          policies,
          feeRecycle: await readFeeRecycle(deps.sql),
        },
      }
    }),

    /* ---------------------------------------------------------------- the estate view */

    define('GET', '/v1/estate', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const view = await composeEstate({
        sql: deps.sql,
        ledger: deps.ledger,
        market: deps.market,
        readiness: deps.readiness,
        // Forwarded, so market records which administrator read the moderation queue.
        operatorBearer: operatorBearer(ctx),
        ...(deps.now ? { now: deps.now } : {}),
      })
      for (const [tile, value] of Object.entries(view)) {
        deps.metrics.increment('admin_estate_tile_status_total', { tile, status: value.status })
      }
      ctx.log.info('estate composed', { operator })
      // ── ALWAYS 200. A dead upstream marks one tile; it does not blank the console. See the
      // header of `estate.ts` for why that matters more here than on a user dashboard.
      return { status: 200, body: view }
    }),
  ]
}

/* ------------------------------------------------------------------------ execution */

interface ExecutionSummary {
  readonly approval: Approval
  readonly detail: Record<string, unknown>
}

/**
 * Run an approved action and record the outcome.
 *
 * Both paths write: a success records `succeeded` with the upstream's answer, a failure records
 * `failed` with the reason. A failure that recorded nothing would leave an approved row that looks
 * as though nobody had tried, and the next operator would authorise it again.
 */
async function execute(
  deps: ServerDeps,
  approval: Approval,
  operator: string,
  bearer: string,
  ctx: RequestContext,
): Promise<ExecutionSummary> {
  const executor = EXECUTORS[approval.action]
  if (!executor) {
    // Unreachable through the route — `POST /v1/approvals` refuses a blocked action — and left
    // here because a catalogue entry added without an executor must not silently succeed.
    const spec = ACTIONS[approval.action]
    throw new ActionUnavailableError(approval.action, spec?.blockedReason ?? 'no executor registered')
  }

  const context: ExecutionContext = {
    approval,
    operatorBearer: bearer,
    operator,
    correlationId: ctx.requestId,
    ledger: deps.ledger,
    market: deps.market,
    billing: deps.billing,
    identity: deps.identity,
    sql: deps.sql,
  }

  let detail: Record<string, unknown>
  let outcome: 'succeeded' | 'failed'
  try {
    detail = await executor(context)
    outcome = 'succeeded'
  } catch (err) {
    outcome = 'failed'
    detail = {
      error: err instanceof UpstreamError ? err.message : 'the action could not be completed',
      upstream: err instanceof UpstreamError ? err.upstream : null,
      status: err instanceof UpstreamError ? err.status : null,
    }
    ctx.log.error('an authorised action failed to execute', { approvalId: approval.id, err })
  }

  const recorded = await deps.sql.begin(async (tx) => ({
    value: await recordExecution(
      tx,
      { id: approval.id, outcome, detail, actor: operator, correlationId: ctx.requestId },
      deps.now,
    ),
  }))
  deps.metrics.increment('admin_operator_actions_total', { action: approval.action, outcome })

  if (outcome === 'failed') {
    // Rethrown AFTER the record commits, so the operator's console shows the failure and the row
    // shows that it was attempted. Recording and then swallowing would be worse than not recording.
    throw new UpstreamError(
      String(detail['upstream'] ?? 'upstream'),
      String(detail['error'] ?? 'the action could not be completed'),
      typeof detail['status'] === 'number' ? detail['status'] : null,
      typeof detail['status'] === 'number' && detail['status'] < 500,
    )
  }

  return { approval: recorded.value?.approval ?? approval, detail }
}

/* ------------------------------------------------------------------------ helpers */

/**
 * Require an `Idempotency-Key` on a mutating route, and answer 400 without one.
 *
 * Named so `routeidempotency.test.ts` can find it by reading this file's source. The guard is a
 * source-level test on purpose: the defect it catches is an OMISSION, and an omission has no
 * behaviour to test.
 */
async function withIdempotentRoute(
  ctx: RequestContext,
  route: string,
  run: () => Promise<Reply>,
): Promise<Reply> {
  const key = headerOf(ctx.req, 'idempotency-key')
  if (!key || key.length < 8 || key.length > 200) {
    throw new BadRequestError(
      `${route} requires an Idempotency-Key header of 8 to 200 characters — a retried request must not create a second artefact`,
    )
  }
  return run()
}

function idempotencyKeyOf(ctx: RequestContext): string {
  return headerOf(ctx.req, 'idempotency-key') ?? ''
}

/**
 * Read the mirrored audit claim out of an inbound envelope.
 *
 * **The `source` is taken from the authenticated sender, not from the payload.** A service that
 * holds `admin:audit:write` can mirror its own rows; it may not mirror somebody else's. Trusting a
 * payload field there would let any one compromised service write audit rows attributed to every
 * other, which is the same act-as-anyone defect as a `userId` parameter, one layer up.
 */
function parseState(value: string): ApprovalState {
  if (value !== 'pending' && value !== 'approved' && value !== 'rejected' && value !== 'expired') {
    throw new BadRequestError('state must be pending, approved, rejected or expired')
  }
  return value
}

function parseCursor(value: string): bigint {
  if (!/^\d{1,19}$/.test(value)) throw new BadRequestError('a cursor is a decimal sequence number')
  return BigInt(value)
}

function parseLimit(value: string | null, fallback = 50, max = 200): number {
  if (value === null) return fallback
  if (!/^\d{1,7}$/.test(value)) throw new BadRequestError('limit must be a whole number')
  return Math.min(Math.max(Number(value), 1), max)
}

function parseDate(value: string, field: string): Date {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) throw new BadRequestError(`${field} must be an ISO 8601 timestamp`)
  return date
}

/**
 * A path parameter compared against a `uuid` column.
 *
 * Checked in the application rather than left to Postgres, because Postgres answers a malformed
 * uuid with error 22P02 — which reaches the error handler as an unrecognised fault and becomes a
 * 500. A caller typing a wrong id would then get "something went wrong on our side" for a request
 * that was simply about a thing that does not exist.
 */
function itemIdOf(ctx: RequestContext): string {
  const id = ctx.params['id'] ?? ''
  if (!UUID.test(id)) throw new NotFoundError('no such item')
  return id
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field]
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new BadRequestError(`${field} is required and must be a non-empty string`)
  }
  return value
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

async function readRaw(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Capped before buffering, not after: an unbounded body is a memory exhaustion primitive that
    // any authenticated caller could otherwise reach.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks)
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readRaw(req)
  if (raw.length === 0) return {}
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new BadRequestError('the request body must be a JSON object')
    }
    return parsed as Record<string, unknown>
  } catch (err) {
    if (err instanceof BadRequestError) throw err
    throw new BadRequestError('the request body is not valid JSON')
  }
}

function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  const headers: Record<string, string> = {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'x-request-id': requestId,
    // An operator console is the one surface where a cached answer during an incident is actively
    // dangerous: acting on a ninety-second-old "ledger: ok" is acting on a fact that has changed.
    'cache-control': 'no-store',
  }
  const payload = reply.text ?? (reply.body === undefined ? '' : `${JSON.stringify(reply.body)}\n`)
  for (const [key, value] of Object.entries(reply.headers ?? {})) headers[key.toLowerCase()] = value
  headers['content-length'] = String(Buffer.byteLength(payload))
  res.writeHead(reply.status, headers)
  res.end(payload)
}
