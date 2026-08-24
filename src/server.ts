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
import { NetworkUnknownError, requestNetwork, type Network } from '@cloudsforge/http'
import type { NetworkSql } from '@cloudsforge/db'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { READ_SCOPE, requireExactScope } from './scopes.ts'
import {
  ACTIONS,
  EXECUTORS,
  REVOCABLE_ROLES,
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
  parseCapWei,
  parseTransferWei,
  parseWei,
  RaiseNeedsApprovalError,
  readFeeRecycle,
  setFeeRecycle,
  setPolicy,
  transferTotals,
  FEE_RECYCLE_CEILING_BPS,
  SEED_PER_DAY_CEILING_WEI,
  SEED_PER_MARKET_CEILING_WEI,
  TRANSFER_CAP_CEILING_WEI,
} from './engagement.ts'
import {
  ApprovalError,
  ApprovalNotFoundError,
  ApprovalStateError,
  REASON_CODES,
  SelfApprovalError,
  SubjectApprovalError,
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
import {
  BACKUP_RESTORE,
  BACKUP_RUN,
  BackupError,
  CEILINGS,
  EnvironmentMismatchError,
  artefactToJson,
  backupToJson,
  enqueueBackupJob,
  expectedConfirmation,
  findBackup,
  listArtefacts,
  listBackups,
  listRestores,
  listRestoresFor,
  protectionFor,
  readEstateIdentity,
  readSettings,
  requestBackup,
  requestRestore,
  restoreToJson,
  settingsToJson,
  updateSettings,
  type BackupKind,
  type BackupState,
} from './backups.ts'
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
import { eraseSubject } from './erasure.ts'
// The registry, and the one place that decides which topics the operator audit log carries.
// Read rather than restated: a decision copied into a consumer is a decision that drifts.
import { auditRowFor, isRegisteredTopic, validateEnvelope, verifyDelivery } from '@cloudsforge/contracts-events'
import { UpstreamError, type BillingClient, type Upstreams, type IdentityClient, type LedgerClient, type MarketClient, type NdaClient, type NotifyClient, type WorldStatus } from './upstreams.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

const MAX_BODY_BYTES = 256 * 1024
const SAFE_REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** The one topic this service does more with than mirror. See `src/erasure.ts`. */
const USER_DELETED_TOPIC = 'identity.user.deleted'

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
  /**
   * The per-network SELECTOR, not a handle. Routes use `ctx.sql`; `NetworkSql` has no query
   * methods, so reaching for the process-wide handle does not compile.
   */
  readonly sql: NetworkSql
  /**
   * The network to assume when no `CF-Network` arrives, or `undefined` to refuse. `CF_NETWORK_SINGLE`,
   * for `pnpm dev`, which has no gateway in front of it. Never set in production.
   */
  readonly singleNetwork?: Network
  readonly producer: string
  /**
   * The six peers, as a per-network SELECTOR. `forRequest` spreads this estate's set over the six
   * fields below before any route runs.
   *
   * admin-api reverses ledger entries, grants roles and delists listings — every one of those is a
   * WRITE to a peer, so a peer narrowed to the wrong estate carries it out there and reports
   * success. The database handle is only half of this service's isolation.
   */
  readonly upstreamsFor: Pick<Upstreams, 'for'>
  readonly ledger: LedgerClient
  readonly market: MarketClient
  readonly billing: BillingClient
  /** Only `identity.role.grant` uses it, and it is the only call that presents the service token
   *  because identity's role gate refuses an operator bearer outright. See `upstreams.ts`. */
  readonly identity: IdentityClient
  readonly notify: NotifyClient
  /** Forge Worlds' game service. The Worlds screen is a proxy onto it — see `upstreams.ts`. */
  readonly nda: NdaClient
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
  /** Which estate this is. Checked against the immutable `estate_identity` row at boot. */
  readonly estateEnvironment: 'mainnet' | 'testnet' | 'development'
  /** Which compose project's volumes a backup taken here names. Descriptive, not a gate. */
  readonly composeProject: string
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
      name: 'admin_subject_approvals_refused_total',
      help:
        'Attempts by an operator to decide a request that names them as its subject. Separate ' +
        'from the self-approval counter because the two say different things about who tried.',
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
    // ──────────────────────────────────────────────────────────────────────────────────────────
    // micro-org #222. The two gauges that answer "can this process authenticate right now", which
    // is the question that had no answer anywhere while `ADMIN_API_SERVICE_TOKEN` sat expired for
    // 26 hours on a container reporting healthy. Sampled in `beforeScrape`; see `index.ts` for why
    // this is a gauge rather than a readiness probe.
    // ──────────────────────────────────────────────────────────────────────────────────────────
    .register({
      name: 'admin_api_service_token_usable',
      help: '1 when a live service token is held. NOT "a token is present" — an expired token is retained on purpose.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'admin_api_service_token_expires_in_seconds',
      help: 'Seconds until the held service token expires. Goes NEGATIVE while identity is unreachable, which is the signal.',
      kind: 'gauge',
      labels: [],
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
  /**
   * The network THIS REQUEST belongs to, from the `CF-Network` header the gateway stamped.
   *
   * Not a property of the process: one pod serves both estates since the network consolidation
   * (micro-deploy `docs/network-consolidation.md`), so "which network am I" has no answer.
   */
  readonly network: Network
  /**
   * The database handle for `network`, resolved ONCE, at the edge of the request.
   *
   * Every route uses this rather than reaching for the process-wide handle, because a wrong handle
   * is not an error — it is a query that SUCCEEDS against the other estate's rows and says nothing.
   * `deps.sql` is a `NetworkSql` with no query methods, so the mistake does not compile.
   */
  readonly sql: Db
}

/**
 * Routes that answer without belonging to a network.
 *
 * Kubelet probes the first two and Prometheus scrapes the third; none arrives through the gateway,
 * so none carries `CF-Network`. Refusing them turns a data-isolation rule into a CrashLoopBackOff —
 * which is exactly what agora's first build did: 500 on every probe, container never ready.
 *
 * A literal SET rather than a prefix, because this is an exemption from a data boundary and
 * widening it should be a deliberate edit. Every member must answer without touching the database.
 */
const OPERATIONAL_ROUTES: ReadonlySet<string> = new Set(['/livez', '/readyz', '/metrics'])

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

/**
 * The body exceeded `MAX_BODY_BYTES` and was refused before it was buffered.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **IT IS ITS OWN ERROR BECAUSE THE CONNECTION MUST BE CLOSED, NOT JUST ANSWERED.**
 *
 * `readRaw` stops consuming the request the moment the cap is passed, which is the whole point —
 * buffering first and checking after is the memory-exhaustion primitive it exists to remove. But
 * that leaves UNREAD BYTES in the socket. On a keep-alive connection the next request is then
 * parsed starting from the middle of the abandoned body, and the client sees `ECONNRESET` on a
 * request that was perfectly well formed.
 *
 * Found by a test: an operator-surface authorisation check placed immediately after the
 * oversized-body test failed with `ECONNRESET` after six seconds, and passed in isolation. The
 * victim is always the NEXT caller to reuse the connection, which is what makes this the kind of
 * defect that reads as a flaky network rather than as a bug.
 *
 * So the reply carries `connection: close`. One refused request costs one connection, which is the
 * correct price and is what every other server does here.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
class BodyTooLargeError extends Error {
  constructor() {
    super('request body too large')
    this.name = 'BodyTooLargeError'
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

    const finish = (status: number, metricNetwork: string) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method,
        route: routeLabel,
        status: String(status),
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, {
        method,
        route: routeLabel,
        network: metricNetwork,
      })
    }

    // ── THE NETWORK, THEN THE HANDLE, BEFORE ANY ROUTE RUNS ──────────────────────────────────
    //
    // `requestNetwork` REFUSES an unstamped request rather than assuming mainnet: a 500 is a
    // routing fault made loud, where a default is a cross-network write nothing would ever flag.
    //
    // The operational endpoints are exempt because kubelet and Prometheus do not come through the
    // gateway and never send the header. Refusing them makes the pod never become ready.
    const networkless = matched !== undefined && OPERATIONAL_ROUTES.has(matched.path)
    let network: Network
    try {
      network = networkless
        ? (deps.singleNetwork ?? deps.sql.networks[0] ?? 'mainnet')
        : requestNetwork(req.headers, deps.singleNetwork ? { fallback: deps.singleNetwork } : {})
    } catch (err) {
      log.error('request carries no usable network', {
        err: err instanceof NetworkUnknownError ? err.message : err,
      })
      send(
        res,
        errorReply(500, 'network_unknown', 'this request could not be attributed to a network', requestId),
        requestId,
      )
      finish(500, 'unknown')
      return
    }

    // ── RESOLVED INSIDE A TRY, AND THAT IS NOT DEFENSIVE PADDING ───────────────────────────────
    //
    // `deps.sql.for()` THROWS when this deployment holds no handle for that network, and that
    // refusal is the safety property the consolidation rests on — better a loud 500 than a query
    // answered out of the other estate's rows.
    //
    // It runs BEFORE `handle` returns a promise, so an uncaught throw escapes the `void` expression
    // past a `.catch` that is not attached yet, and the listener returns having sent NOTHING. The
    // connection then hangs until the client gives up: the one path the design most depends on
    // being loud was the one path that was silent.
    // `forRequest` is resolved HERE, not on the dispatch line, and that placement is the whole
    // point. It rebuilds this request's domain objects, and in the services that bulkhead their
    // job queues it reaches a per-network plane that throws just as hard as the handle does.
    // One line lower it was OUTSIDE this try and still synchronous — so the throw was an
    // unhandled exception in a request listener, and node exits on those. The pod died on the
    // first request naming a network it did not hold, and its replacement died on the next one.
    let sql: Db
    let scoped: ReturnType<typeof forRequest>
    try {
      sql = deps.sql.for(network) as unknown as Db
      scoped = forRequest(deps, network)
    } catch (err) {
      log.error('no usable database handle for this request', { err, network })
      send(
        res,
        errorReply(500, 'network_unavailable', 'this deployment cannot serve that network', requestId),
        requestId,
      )
      finish(500, network)
      return
    }
    void handle(matched, { req, url, requestId, log, params, network, sql }, scoped)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status, network)
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500, network)
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
/**
 * The deps a REQUEST sees: this estate's handle, and this estate's peers.
 *
 * Both halves matter and the second is the easier one to forget. admin-api reverses ledger
 * entries, grants roles and delists listings — every one of those is a WRITE to a peer, and a
 * peer narrowed to the wrong estate carries it out there. The operator sees a success.
 */
function forRequest(deps: ServerDeps, network: Network): ServerDeps {
  return { ...deps, ...deps.upstreamsFor.for(network) }
}

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
    if (err instanceof SubjectApprovalError) {
      deps.metrics.increment('admin_subject_approvals_refused_total')
      // Warn, and a DIFFERENT code from `self_approval_refused` — micro-org#317. An operator who
      // is told "you cannot approve your own request" after approving somebody else's concludes
      // the service is broken and goes looking for another route, which is the opposite of what a
      // refusal is for. The two are also worth counting apart: a self-approval attempt is nearly
      // always a UI offering a button it should not have, while a decision on a request that names
      // the decider is a person who has read the queue and picked that row.
      ctx.log.warn('subject-approval refused')
      return errorReply(403, 'subject_approval_refused', err.message, ctx.requestId)
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
    if (err instanceof BodyTooLargeError) {
      // 400 rather than 413 to keep the existing contract, but the connection goes: see the class.
      return {
        status: 400,
        headers: { connection: 'close' },
        body: { error: { code: 'bad_request', message: err.message, requestId: ctx.requestId } },
      }
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
     * `deploy/README.md` had already recorded as making 17 §7 claim 9 unpassable. **An empty
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

      const outcome = await withInbox(ctx.sql, topic, eventId, async (tx) => {
        const appended = await appendAudit(
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
        )

        // ════════════════════════════════════════════════════════════════════════════════════
        // GDPR erasure, on top of the mirror rather than instead of it.
        //
        // `identity.user.deleted` is `audited: true` in `TOPIC_AUDIT`
        // (`contracts/packages/events/src/audit.ts`), so the event that REQUESTS the erasure
        // appends its own audit row above naming the subject. That row is kept deliberately: it
        // is the evidence that the request was received and acted on, which is precisely what
        // Art. 5(2) accountability asks for. It is then restricted on read like every other row
        // about that subject.
        //
        // Everything that follows — why the chain is not rewritten, which Article retains it,
        // what IS erased and what is merely restricted, and the per-table decision — is the
        // header of `src/erasure.ts`. It lives there and not here because it is long, and
        // because it must sit beside the code that implements it rather than beside the
        // dispatch that calls it.
        //
        // In the SAME transaction as the mirror and the inbox claim, so the audit row, the
        // register entry and the acknowledgement cannot disagree about whether this happened.
        // ════════════════════════════════════════════════════════════════════════════════════
        if (topic !== USER_DELETED_TOPIC) return { audit: appended, erasure: null }

        const payload = event.payload as Record<string, unknown>
        // `payload.userId`, not `envelope.actor`: on this topic the actor is whoever ASKED for
        // the deletion, which is the deleted user only when they deleted themselves.
        const named = typeof payload['userId'] === 'string' ? payload['userId'] : ''
        // identity sends a bare uuid; the `user:<uuid>` ledger spelling is stripped explicitly
        // because `audit_events.subject_id` and `approvals.subject_id` hold the bare form.
        const userId = named.startsWith('user:') ? named.slice('user:'.length) : named
        if (!UUID.test(userId)) {
          throw new BadRequestError('identity.user.deleted requires a uuid userId')
        }
        const erasure = await eraseSubject(tx, {
          userId,
          sourceEventId: eventId,
          tombstoneAt: typeof payload['tombstoneAt'] === 'string' ? payload['tombstoneAt'] : null,
          reason: typeof payload['reason'] === 'string' ? payload['reason'] : null,
        })
        return { audit: appended, erasure }
      })
      if (outcome.status === 'duplicate') {
        return { status: 200, body: { status: 'duplicate', eventId } }
      }
      deps.metrics.increment('admin_audit_events_total', {
        source: sender,
        outcome: mirrored.outcome,
      })
      const erasure = outcome.value.erasure
      if (erasure) {
        // Counts and column names only. Never the subject id.
        ctx.log.info('subject erasure registered', {
          registered: erasure.registered,
          approvalsAnonymised: erasure.approvalsAnonymised,
          auditRowsRestricted: erasure.auditRowsRestricted,
        })
      }
      return {
        status: 201,
        body: {
          status: 'recorded',
          seq: outcome.value.audit.seq.toString(),
          hash: outcome.value.audit.hash,
          ...(erasure ? { erasure } : {}),
        },
      }
    }),

    /* ---------------------------------------------------------------- audit reads */

    /* ---------------------------------------------------------------- mail history */

    /**
     * What was sent to this person, and did it arrive.
     *
     * A read, so `requireReader` — support answering "I never got the email" should not need the
     * same authority as reversing a ledger entry. Notify's own route is `requireAdmin` and refuses
     * a service principal outright, which is why the OPERATOR's bearer is forwarded rather than
     * this service's token: the authorisation decision stays with notify, against the real human.
     *
     * One of `user` or `address` is required. Unscoped, notify's route is the estate-wide
     * dead-letter view and answers a different question; serving that here under a name promising
     * one person's mail would be the sort of quiet mismatch an operator acts on without noticing.
     */
    define('GET', '/v1/mail', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      const params = ctx.url.searchParams
      const user = params.get('user')
      const address = params.get('address')
      if (!user && !address) {
        throw new BadRequestError('one of user or address is required')
      }
      const limit = Number(params.get('limit') ?? '50')
      const page = await deps.notify.mailFor({
        ...(user ? { userId: user } : {}),
        ...(address ? { address } : {}),
        limit: Number.isFinite(limit) && limit > 0 && limit <= 200 ? limit : 50,
        bearer: operatorBearer(ctx),
        correlationId: ctx.requestId,
      })
      return { status: 200, body: page }
    }),

    /**
     * Send it again.
     *
     * `requireOperator`, not `requireReader`: this puts a message in front of a person, and a
     * read-scoped service token must not be able to. Notify answers 202 and queues a NEW delivery
     * beside the original, so the failure being repeated stays readable afterwards — that status
     * is passed straight through rather than flattened to 200, because nothing has been sent when
     * this returns.
     */
    define('POST', '/v1/mail/:id/resend', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const id = ctx.params['id'] ?? ''

      // ── WRAPPED, BECAUSE A RETRY HERE SENDS A SECOND EMAIL ────────────────────────────────
      //
      // Notify refuses to resend a delivery that is already `pending`, which stops a double
      // click on the SAME row. It does not stop this: a retried HTTP request resends the
      // original — still `dead`, still eligible — and queues a second delivery. Two messages to
      // one person for one operator action, which is exactly the durable artefact per retry that
      // `routeidempotency.test.ts` exists to catch. It caught this one.
      return withIdempotentRoute(ctx, '/v1/mail/:id/resend', async () => {
        const outcome = await withIdempotency(ctx.sql, {
          principal: operator,
          route: '/v1/mail/:id/resend',
          clientKey: idempotencyKeyOf(ctx),
          // The delivery id IS the request: there is no body. Two operators resending the same
          // failed message are asking for one thing, and the fingerprint says so.
          requestHash: requestFingerprint({ deliveryId: id }),
          run: async () => {
            const answer = await deps.notify.resend({
              deliveryId: id,
              bearer: operatorBearer(ctx),
              correlationId: ctx.requestId,
            })
            return { response: answer, artefactId: answer.deliveryId }
          },
        })
        ctx.log.info('operator resent a delivery', {
          operator,
          deliveryId: id,
          created: outcome.result.deliveryId,
          replayed: outcome.replayed,
        })
        return { status: 202, body: outcome.result }
      })
    }),

    define('GET', '/v1/audit', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const reader = requireReader(principal)
      const params = ctx.url.searchParams
      const before = params.get('before')
      const page = await readAudit(ctx.sql, {
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
      const result = await verifyChain(ctx.sql, {
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
      const approvals = await listApprovals(ctx.sql, {
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
      const approval = await findApproval(ctx.sql, itemIdOf(ctx))
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
        const amount = parseTransferWei(String(params['amountWei']))
        const policy = await findPolicy(ctx.sql, service)
        if (!policy) {
          throw new BadRequestError(
            `no engagement policy exists for ${service} — the caps must exist before anything moves (21 §8); ` +
              'raise one through engagement.policy.set first',
          )
        }
        if (amount > BigInt(policy.transferCapWei)) {
          throw new BadRequestError(
            `a transfer of ${amount} wei of EMBER exceeds engagement:${service}'s policy cap of ${policy.transferCapWei}`,
          )
        }
      }
      // ── Same reasoning, one action along — micro-org#317. `identity.role.revoke` may only name
      // a role in `REVOCABLE_ROLES`, because identity's write REPLACES the role set and the
      // executor cannot read what the subject currently holds, so anything outside that list would
      // be a set-replacement nobody reviewed. The executor refuses it too and remains the
      // enforcement of record; this is here so the refusal arrives BEFORE two operators sign,
      // rather than as a failed execution on an approval that can never complete.
      if (action === 'identity.role.revoke' && !REVOCABLE_ROLES.includes(String(params['role']))) {
        throw new BadRequestError(
          `params.role must be one of ${REVOCABLE_ROLES.join(', ')} for ${action} — revoking anything ` +
            'else would mean replacing the whole role set, and identity exposes no read of what ' +
            'this user currently holds',
        )
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
        if (typeof params['transferCapWei'] === 'string') parseCapWei(params['transferCapWei'])
        if (typeof params['seedPerMarketWei'] === 'string') parseWei(params['seedPerMarketWei'])
        if (typeof params['seedPerDayWei'] === 'string') parseWei(params['seedPerDayWei'])
        if (service === 'platform' && typeof params['recycleBps'] !== 'string') {
          throw new BadRequestError('params.recycleBps is required to set the fee recycle')
        }
      }

      return withIdempotentRoute(ctx, '/v1/approvals', async () => {
        const outcome = await withIdempotency(ctx.sql, {
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
        const outcome = await withIdempotency(ctx.sql, {
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
        //
        // ── AND THERE IS NO SEPARATE EXECUTE STEP. THAT IS A DECISION — micro-org#317. ──
        //
        // The second signature and the trigger are ONE HTTP call. The approver is therefore always
        // the executor, and there is no window in which an approved-but-unrun action sits waiting
        // to be inspected, delayed or withdrawn. #317 asked whether that was chosen or inherited.
        // It is chosen, and the argument is this:
        //
        //   * A separate execute step adds a THIRD moment a human must show up, and it is the
        //     moment with the least information attached — the decision has already been made and
        //     recorded, so whoever presses it is either re-litigating a signed approval or is a
        //     rubber stamp. This estate has one control that depends entirely on operators not
        //     signing reflexively, and adding a step that teaches them to is how it is lost.
        //     `ActionSpec.approval = 'read'` exists for the same reason, one layer up.
        //   * The window would not be a review window unless something WATCHED it, and nothing
        //     does: there is no notification on any action here (#165's gap), so an approved row
        //     would sit unread until the person who approved it came back for it.
        //   * The delay is not free. Six of the seven executable actions reverse a bad ledger
        //     entry, resolve a moderation case, revoke an entitlement or fund an engagement
        //     account — all of them things somebody is waiting on during an incident, and all of
        //     them reversible afterwards.
        //
        // **THE ONE ACTION THIS ARGUMENT DOES NOT COVER IS `estate.restore`**, which overwrites
        // every database in the estate including the audit rows that would say who did it. The
        // coupling is deliberately NOT the last checkpoint there, and that is why the executor
        // only QUEUES the restore rather than performing it: the queued row is a real window, held
        // by `deploy/backup`'s runner rather than by this route. See `EXECUTORS['estate.restore']`
        // in actions.ts for what that window can and cannot currently do — it is not yet possible
        // to withdraw a queued restore, and closing that is named in #317 as micro-deploy's.
        // ══════════════════════════════════════════════════════════════════════════════════
        const execution = await execute(deps, approval, operator, bearer, ctx)
        return { status: 201, body: { approval: execution.approval, execution: execution.detail } }
      })
    }),

    /* ---------------------------------------------------------------- flags */

    define('GET', '/v1/flags', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      return { status: 200, body: { flags: await listFlags(ctx.sql) } }
    }),

    define('PUT', '/v1/flags/:key', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)
      const enabled = body['enabled']
      if (typeof enabled !== 'boolean') throw new BadRequestError('enabled must be true or false')

      const result = await ctx.sql.begin(async (tx) => ({
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
          broadcasts: await listBroadcasts(ctx.sql, {
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
        const outcome = await withIdempotency(ctx.sql, {
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
      const result = await ctx.sql.begin(async (tx) => ({
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
          policies: await listPolicies(ctx.sql),
          feeRecycle: await readFeeRecycle(ctx.sql),
          // The schema ceilings, served so a console can render the bounds an operator is
          // choosing inside — the same numbers migrations.ts version 8 CHECKs.
          ceilings: {
            transferCapWei: TRANSFER_CAP_CEILING_WEI.toString(),
            seedPerMarketWei: SEED_PER_MARKET_CEILING_WEI.toString(),
            seedPerDayWei: SEED_PER_DAY_CEILING_WEI.toString(),
            feeRecycleBps: FEE_RECYCLE_CEILING_BPS,
          },
        },
      }
    }),

    /**
     * The LOWERING lane — one operator, no queue. The devplatform asymmetry
     * (devplatform/src/server.ts): lowering a cap narrows what can move and is the operator
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
        const result = await ctx.sql.begin(async (tx) => ({
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
        ...(typeof body['transferCapWei'] === 'string'
          ? { transferCapWei: parseCapWei(body['transferCapWei']) }
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
          'nothing to change — send transferCapWei, or seedPerMarketWei and seedPerDayWei (null clears the pair)',
        )
      }
      const result = await ctx.sql.begin(async (tx) => ({
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
      const policies = await listPolicies(ctx.sql)
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
          spendWeiByService: await transferTotals(ctx.sql),
          transfers: await listTransfers(ctx.sql),
          policies,
          feeRecycle: await readFeeRecycle(ctx.sql),
        },
      }
    }),

    /* ---------------------------------------------------------------- the estate view */

    define('GET', '/v1/estate', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const view = await composeEstate({
        sql: ctx.sql,
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

    /* ---------------------------------------------------------------- backup and restore */

    /**
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * **EVERY ROUTE BELOW IS `requireOperator`, INCLUDING THE READS.**
     *
     * `requireReader` — which admits a service token holding `admin:read` — is deliberately NOT
     * used here, and this is the one place in the file that departs from that pattern. A backup
     * listing names the directory the artefacts are in, the databases they cover and the checksums
     * that authenticate them; that is a map of where the estate's data is kept, and a read-only
     * service credential is a credential that lives in a container's environment. An unauthenticated
     * or under-authenticated restore is a total compromise, and the read is most of the way to one.
     *
     * `adminOnly` in `ui/packages/ui/src/surfaces.ts` is a NAVIGATION filter and not a boundary —
     * `admin-web/src/lib/auth.tsx` says so in as many words. This is the boundary.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    define('GET', '/v1/backups', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireOperator(principal)
      const params = ctx.url.searchParams
      const state = params.get('state')
      const settings = await readSettings(ctx.sql)
      const backups = await listBackups(ctx.sql, {
        ...(state ? { state: parseBackupState(state) } : {}),
        limit: parseLimit(params.get('limit')),
      })
      const identity = await readEstateIdentity(ctx.sql)
      return {
        status: 200,
        body: {
          backups: backups.map(backupToJson),
          settings: settingsToJson(settings),
          // The honesty block. Two lists rather than a status, because a status invites a green
          // tick and a green tick is a claim this estate cannot support. See `backups.ts`.
          protection: protectionFor(settings),
          estate: {
            environment: identity?.environment ?? null,
            composeProject: deps.composeProject,
          },
        },
      }
    }),

    define('GET', '/v1/backups/settings', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireOperator(principal)
      const settings = await readSettings(ctx.sql)
      return {
        status: 200,
        body: {
          settings: settingsToJson(settings),
          // The schema's own bounds, so a console renders the range an operator is choosing inside
          // rather than discovering it as a 400 — the same shape as the engagement ceilings above.
          ceilings: {
            retentionCopies: CEILINGS.retentionCopies,
            ceilingBytes: {
              min: CEILINGS.ceilingBytes.min.toString(),
              max: CEILINGS.ceilingBytes.max.toString(),
            },
            minFreeBytes: {
              min: CEILINGS.minFreeBytes.min.toString(),
              max: CEILINGS.minFreeBytes.max.toString(),
            },
            scheduleEveryMinutes: CEILINGS.scheduleEveryMinutes,
            verifyEveryMinutes: CEILINGS.verifyEveryMinutes,
          },
          protection: protectionFor(settings),
        },
      }
    }),

    define('PUT', '/v1/backups/settings', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)

      const change = {
        ...(typeof body['rootPath'] === 'string' ? { rootPath: body['rootPath'] } : {}),
        ...(typeof body['retentionCopies'] === 'number'
          ? { retentionCopies: body['retentionCopies'] }
          : {}),
        ...(typeof body['ceilingBytes'] === 'string'
          ? { ceilingBytes: parseByteCount(body['ceilingBytes'], 'ceilingBytes') }
          : {}),
        ...(typeof body['minFreeBytes'] === 'string'
          ? { minFreeBytes: parseByteCount(body['minFreeBytes'], 'minFreeBytes') }
          : {}),
        ...(typeof body['scheduleEnabled'] === 'boolean'
          ? { scheduleEnabled: body['scheduleEnabled'] }
          : {}),
        ...(typeof body['scheduleEveryMinutes'] === 'number'
          ? { scheduleEveryMinutes: body['scheduleEveryMinutes'] }
          : {}),
        ...(typeof body['verifyEnabled'] === 'boolean' ? { verifyEnabled: body['verifyEnabled'] } : {}),
        ...(typeof body['verifyEveryMinutes'] === 'number'
          ? { verifyEveryMinutes: body['verifyEveryMinutes'] }
          : {}),
      }
      if (Object.keys(change).length === 0) {
        throw new BadRequestError('nothing to change')
      }

      const result = await ctx.sql.begin(async (tx) => {
        const settings = await updateSettings(tx, change, operator)
        // Changing where the estate's backups are written is an operator action on the estate's
        // recoverability, so it takes an audit row like any other. The row names the new root and
        // the old one: "where were the backups going in March" is a question an incident asks.
        await appendAudit(
          tx,
          {
            actor: operator,
            action: 'admin.backup.settings.changed',
            subjectKind: 'backup_settings',
            subjectId: 'singleton',
            outcome: 'allowed',
            correlationId: ctx.requestId,
            payload: { ...settingsToJson(settings) },
          },
          deps.now,
        )
        return { value: settings }
      })
      deps.metrics.increment('admin_operator_actions_total', {
        action: 'backup.settings.changed',
        outcome: 'allowed',
      })
      return { status: 200, body: { settings: settingsToJson(result.value) } }
    }),

    define('GET', '/v1/backups/:id', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireOperator(principal)
      const backup = await findBackup(ctx.sql, itemIdOf(ctx))
      if (!backup) throw new NotFoundError(`no backup run ${ctx.params['id']}`)
      return {
        status: 200,
        body: {
          backup: backupToJson(backup),
          // Names and checksums. NEVER contents — see the header of `backups.ts`: the console must
          // be able to show that a custody backup exists without showing what is in it.
          artefacts: (await listArtefacts(ctx.sql, backup.id)).map(artefactToJson),
          restores: (await listRestoresFor(ctx.sql, backup.id)).map(restoreToJson),
          // Rendered so the operator can read the phrase before they are asked to type it, and so
          // the second approver sees exactly the string the first one agreed to.
          liveConfirmationPhrase: expectedConfirmation(backup),
        },
      }
    }),

    /**
     * Take a backup now.
     *
     * Idempotent by header like every other mutating route here, and for a sharper reason than
     * usual: a double-clicked button that queued two full dumps of a 300 MB cluster would write two
     * complete sets to the destination disk, and the retention policy would then evict a genuinely
     * older set to make room for the duplicate.
     */
    define('POST', '/v1/backups', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)
      const kind = typeof body['kind'] === 'string' ? parseBackupKind(body['kind']) : 'full'

      return withIdempotentRoute(ctx, '/v1/backups', async () => {
        const outcome = await withIdempotency(ctx.sql, {
          principal: operator,
          route: '/v1/backups',
          clientKey: idempotencyKeyOf(ctx),
          requestHash: requestFingerprint(body),
          run: async (tx) => {
            const backup = await requestBackup(tx, {
              kind,
              requestedBy: operator,
              reason: typeof body['reason'] === 'string' ? body['reason'] : null,
              composeProject: deps.composeProject,
              correlationId: ctx.requestId,
            })
            // The job and the row commit together. See `enqueueBackupJob` for why this cannot go
            // through `JobQueue`, which holds its own connection.
            await enqueueBackupJob(tx, BACKUP_RUN, `backup:${backup.id}`, { backupRunId: backup.id })
            await appendAudit(
              tx,
              {
                actor: operator,
                action: 'admin.backup.requested',
                subjectKind: 'backup_run',
                subjectId: backup.id,
                outcome: 'allowed',
                correlationId: ctx.requestId,
                payload: { kind, environment: backup.environment, rootPath: backup.rootPath },
              },
              deps.now,
            )
            return { response: { backup: backupToJson(backup) }, artefactId: backup.id }
          },
        })
        deps.metrics.increment('admin_operator_actions_total', {
          action: 'backup.requested',
          outcome: 'allowed',
        })
        return { status: outcome.replayed ? 200 : 201, body: outcome.result }
      })
    }),

    define('GET', '/v1/restores', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireOperator(principal)
      const restores = await listRestores(ctx.sql, parseLimit(ctx.url.searchParams.get('limit')))
      return { status: 200, body: { restores: restores.map(restoreToJson) } }
    }),

    /**
     * Request a restore.
     *
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * **THIS ROUTE ACCEPTS `verify` AND REFUSES `live`. THE ONLY DOOR TO A LIVE RESTORE IS THE
     * APPROVAL QUEUE.**
     *
     * `verify` restores into a throwaway scratch database, checks it, and drops it. It touches
     * nothing live, so it needs one operator and no ceremony — and that asymmetry is load-bearing
     * rather than lenient. "A backup nobody has restored is a wish" is this estate's own hard-won
     * lesson; if the only available restore were the terrifying one, no restore would ever be
     * rehearsed and every backup would stay a wish. Making the safe one cheap is what makes the
     * dangerous one rare.
     *
     * `live` is refused here with the route to use instead, exactly as a read action is refused by
     * `POST /v1/approvals` with the GET to call. Two operators, `estate.restore`, and a typed
     * confirmation the second one can see before signing.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    define('POST', '/v1/restores', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)
      const backupRunId = requireString(body, 'backupRunId')
      if (!UUID.test(backupRunId)) throw new BadRequestError('backupRunId must be a uuid')
      const mode = requireString(body, 'mode')

      if (mode === 'live') {
        throw new BadRequestError(
          'a live restore overwrites live data and cannot be requested directly — raise an ' +
            'estate.restore approval through POST /v1/approvals, which needs a second operator ' +
            'and a typed confirmation naming the backup and the environment',
        )
      }
      if (mode !== 'verify') throw new BadRequestError('mode must be "verify" or "live"')

      const rawTargets = body['targets']
      const targets = Array.isArray(rawTargets)
        ? rawTargets.filter((t): t is string => typeof t === 'string')
        : []

      return withIdempotentRoute(ctx, '/v1/restores', async () => {
        const outcome = await withIdempotency(ctx.sql, {
          principal: operator,
          route: '/v1/restores',
          clientKey: idempotencyKeyOf(ctx),
          requestHash: requestFingerprint(body),
          run: async (tx) => {
            const restore = await requestRestore(tx, {
              backupRunId,
              mode: 'verify',
              targets,
              requestedBy: operator,
              reason: typeof body['reason'] === 'string' ? body['reason'] : null,
              // Both null, and `restore_runs_verify_is_unapproved` refuses a verify row that names
              // an approval — so a caller cannot spend an `estate.restore` approval on a verify and
              // leave the partial unique index thinking it has been used.
              approvalId: null,
              confirmation: null,
              correlationId: ctx.requestId,
            })
            await enqueueBackupJob(tx, BACKUP_RESTORE, `restore:${restore.id}`, {
              restoreRunId: restore.id,
            })
            await appendAudit(
              tx,
              {
                actor: operator,
                action: 'admin.restore.requested',
                subjectKind: 'backup_run',
                subjectId: backupRunId,
                outcome: 'allowed',
                correlationId: ctx.requestId,
                payload: { mode: 'verify', restoreRunId: restore.id, targets },
              },
              deps.now,
            )
            return { response: { restore: restoreToJson(restore) }, artefactId: restore.id }
          },
        })
        deps.metrics.increment('admin_operator_actions_total', {
          action: 'restore.verify.requested',
          outcome: 'allowed',
        })
        return { status: outcome.replayed ? 200 : 201, body: outcome.result }
      })
    }),

    /* ---------------------------------------------------------------- forge worlds */

    /**
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * **THE FIVE ROUTES THAT TAKE *NINETY DAYS AFTER* OUT OF `draft`.**
     *
     * `nda` — the whole game: worlds, tiles, homesteads, the day-resolution engine, communes and
     * reports — has been running and healthy in the estate for weeks with no way to reach it. It
     * has no hostname, so it has no Cloudflare DNS record, no tunnel ingress rule, no Access
     * policy and no Traefik router; and it has no operator screen anywhere. A title nobody can
     * generate a world for is a title nobody can play, which is what `draft` has been recording.
     *
     * These are a PROXY, not a reimplementation. Every one forwards to the route named beside it
     * and adds exactly two things nda cannot do for itself: this console's authentication, and
     * this console's hash-chained audit row naming the operator who acted. The world's own
     * outbox events are still nda's, and they still name the human, because the operator's own
     * bearer is what goes upstream. See the `nda` section of `upstreams.ts`.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */

    define('GET', '/v1/worlds', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      requireReader(principal)
      // ALL THREE statuses, where nda's own default is `lobby,active`. An operator's question on
      // this screen is "what has this estate ever generated", and a finished season is the one
      // worth reading — it is the only evidence the engine ran ninety days without stalling.
      const statuses: readonly WorldStatus[] = ['lobby', 'active', 'archived']
      const worlds = await deps.nda.listWorlds({
        statuses,
        correlationId: ctx.requestId,
        operatorBearer: operatorBearer(ctx),
      })
      return { status: 200, body: { worlds } }
    }),

    define('POST', '/v1/worlds', async (ctx, deps) => {
      const principal = await authenticate(ctx, deps)
      const operator = requireOperator(principal)
      const body = await readJson(ctx.req)
      const key = idempotencyKeyOf(ctx)
      // REQUIRED, and refused here rather than upstream. Generating a world builds a whole map;
      // a double-submitted form without a key would build two worlds and neither would be wrong
      // enough for anything to notice. nda answers a repeat of the same key with the first
      // world and `replayed: true`.
      if (!key) throw new BadRequestError('an Idempotency-Key header is required to create a world')

      const answer = await deps.nda.createWorld({
        name: requireString(body, 'name'),
        ...optionalWholeNumber(body, 'width'),
        ...optionalWholeNumber(body, 'height'),
        ...optionalWholeNumber(body, 'seasonLength'),
        ...optionalWholeNumber(body, 'tickIntervalMinutes'),
        ...(typeof body['seed'] === 'string' && body['seed'].length > 0
          ? { seed: body['seed'] }
          : {}),
        idempotencyKey: key,
        correlationId: ctx.requestId,
        operatorBearer: operatorBearer(ctx),
      })

      await ctx.sql.begin((tx) =>
        appendAudit(
          tx,
          {
            actor: operator,
            action: 'admin.world.created',
            subjectKind: 'world',
            subjectId: answer.world.id,
            outcome: 'allowed',
            correlationId: ctx.requestId,
            // The SEED is recorded, because it is what makes a world reproducible: the same seed
            // and the same inputs resolve byte-identically (`nda/src/engine/state.ts`), so this
            // row is enough to rebuild the map somebody is asking about.
            payload: {
              name: answer.world.name,
              seed: answer.world.seed,
              width: answer.world.width,
              height: answer.world.height,
              seasonLength: answer.world.seasonLength,
              tickIntervalMinutes: answer.world.tickIntervalMinutes,
              replayed: answer.replayed,
            },
          },
          deps.now,
        ),
      )
      deps.metrics.increment('admin_operator_actions_total', {
        action: 'world.created',
        outcome: 'allowed',
      })
      return { status: answer.replayed ? 200 : 201, body: answer }
    }),

    define('POST', '/v1/worlds/:id/start', async (ctx, deps) => {
      const operator = requireOperator(await authenticate(ctx, deps))
      return worldMutation(ctx, deps, operator, 'admin.world.started', 'world.started', async (request) => {
        const answer = await deps.nda.startWorld(request)
        return { body: answer, payload: { status: answer.world.status, replayed: answer.replayed } }
      })
    }),

    define('POST', '/v1/worlds/:id/tick', async (ctx, deps) => {
      const operator = requireOperator(await authenticate(ctx, deps))
      return worldMutation(ctx, deps, operator, 'admin.world.ticked', 'world.ticked', async (request) => {
        const answer = await deps.nda.tickWorld(request)
        // 202, matching nda: the tick is ENQUEUED behind the world's lease, not resolved inline,
        // so an operator's force-tick and the scheduler's sweep cannot both advance the same day.
        return { status: 202, body: answer, payload: { replayed: answer.replayed } }
      })
    }),

    define('PUT', '/v1/worlds/:id/bots', async (ctx, deps) => {
      const operator = requireOperator(await authenticate(ctx, deps))
      const body = await readJson(ctx.req)
      const enabled = body['enabled']
      if (typeof enabled !== 'boolean') throw new BadRequestError('enabled must be true or false')
      const rawCount = body['count']
      const count = enabled ? rawCount : 0
      if (typeof count !== 'number' || !Number.isInteger(count) || count < 0) {
        throw new BadRequestError('count must be a whole number of bots, zero or more')
      }
      return worldMutation(ctx, deps, operator, 'admin.world.bots.changed', 'world.bots.changed', async (request) => {
        const answer = await deps.nda.setBots({ ...request, enabled, count })
        return { body: answer, payload: { enabled, count, bots: answer.bots, replayed: answer.replayed } }
      })
    }),
  ]
}

/**
 * A whole number from a JSON body, or nothing — spread into a request rather than defaulted.
 *
 * `{}` for an absent field, so the upstream applies its OWN default. A `null` or a restated
 * default here would be this service having an opinion about how big a world should be, which is
 * `nda/src/worlds.ts`'s to hold: it bounds width and height to 12..64, the season to 5..365 days
 * and the tick to 1..1440 minutes, and it is the file that changes when those move.
 */
function optionalWholeNumber(
  body: Record<string, unknown>,
  field: string,
): Record<string, number> {
  const value = body[field]
  if (value === undefined || value === null || value === '') return {}
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new BadRequestError(`${field} must be a whole number`)
  }
  return { [field]: value }
}

/**
 * A world id in the shape nda actually stores them.
 *
 * NOT a uuid, which is what this gate said for one commit. `nda/src/migrations.ts` declares
 * `id text primary key` and `mustFindWorld` looks it up as text — `randomUUID()` is only what a
 * world created THROUGH THE API happens to get. The live estate holds `drill-world`, seeded on
 * 2026-08-05 before there was a create route, and a uuid gate answered 400 for it: the operator's
 * very first screen would have listed a world in `lobby` and then refused to start it.
 *
 * So this is the gate it was always meant to be — one that keeps a path segment a path segment.
 * The client `encodeURIComponent`s it regardless; this refuses the shapes that are a mistake
 * rather than a world, and leaves "does it exist" to nda's own 404, which is the only place that
 * can answer it.
 */
const WORLD_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/

/**
 * The three world mutations, which differ only in what they call and what they record.
 *
 * Shared because the parts that are easy to get wrong are the parts that are identical: the
 * operator's bearer forwarded rather than the service's, the `Idempotency-Key` refused when
 * absent rather than invented, and an audit row written whether or not the upstream replayed.
 *
 * ── THE AUTHENTICATION IS NOT IN HERE, AND THAT IS THE POINT ──────────────────────────────────
 *
 * It was, for one commit. `bootstrap.test.ts` refused it: that test reads the source of each route
 * block and requires `await authenticate(ctx, deps)` in the block itself, and a helper is exactly
 * the shape it cannot see through — `POST /v1/worlds/:id/start` and `.../tick` came out of it
 * reading as unauthenticated routes that were not on the pinned list of four.
 *
 * The guard is right and the helper was wrong. A reviewer reading a route has to be able to see
 * that it authenticates without following a call, and a future route that hid its auth behind a
 * DIFFERENT helper would pass a test that had been taught to follow this one. So the caller
 * authenticates in the open and hands the result down.
 */
async function worldMutation(
  ctx: RequestContext,
  deps: ServerDeps,
  operator: string,
  action: string,
  metricAction: string,
  run: (request: {
    readonly worldId: string
    readonly idempotencyKey: string
    readonly correlationId: string
    readonly operatorBearer: string
  }) => Promise<{
    readonly status?: number
    readonly body: unknown
    readonly payload: Record<string, unknown>
  }>,
): Promise<Reply> {
  const worldId = ctx.params['id'] ?? ''
  if (!WORLD_ID.test(worldId)) throw new BadRequestError('that is not the shape of a world id')
  const key = idempotencyKeyOf(ctx)
  if (!key) throw new BadRequestError('an Idempotency-Key header is required')

  const outcome = await run({
    worldId,
    idempotencyKey: key,
    correlationId: ctx.requestId,
    operatorBearer: operatorBearer(ctx),
  })

  await ctx.sql.begin((tx) =>
    appendAudit(
      tx,
      {
        actor: operator,
        action,
        subjectKind: 'world',
        subjectId: worldId,
        outcome: 'allowed',
        correlationId: ctx.requestId,
        payload: outcome.payload,
      },
      deps.now,
    ),
  )
  deps.metrics.increment('admin_operator_actions_total', {
    action: metricAction,
    outcome: 'allowed',
  })
  return { status: outcome.status ?? 200, body: outcome.body }
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
    sql: ctx.sql,
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

  const recorded = await ctx.sql.begin(async (tx) => ({
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
 * Validate an approval `state` query parameter against the closed set the queue can be in.
 *
 * **THE COMMENT THAT WAS HERE DESCRIBED A DIFFERENT FUNCTION ENTIRELY — micro-org#317.** It said
 * this reads "the mirrored audit claim out of an inbound envelope" and argued about taking the
 * `source` from the authenticated sender rather than the payload, on a route gated by
 * `admin:audit:write`. None of that is this function, and two thirds of it no longer describes
 * anything: `admin:audit:write` was deleted (`scopes.ts` records why — no relay could ever present
 * it, so it named a capability exercised zero times) and `POST /v1/events` is MAC-only now. The
 * argument itself is sound and still lives where it belongs, beside that route.
 *
 * How it got here is worth a line, because it is the same defect as #317's headline in miniature:
 * a doc comment was left attached to the helper that used to follow it when the code between them
 * moved. Nothing failed. A comment cannot be typechecked, and there is no test that can be written
 * for "this paragraph is about the function under it" — which is why the rest of this repository
 * spends its comments on measurements and reasons rather than on restating what the code does.
 *
 * The list below is the same closed set as `approvals_state_known` in migrations.ts version 6. It
 * is written out rather than derived from the type so that an unknown value is a 400 naming the
 * four legal ones, not a query that silently matches nothing.
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

function parseBackupState(value: string): BackupState {
  const states = ['queued', 'running', 'succeeded', 'failed', 'pruned']
  if (!states.includes(value)) throw new BadRequestError(`state must be one of ${states.join(', ')}`)
  return value as BackupState
}

function parseBackupKind(value: string): BackupKind {
  const kinds = ['full', 'databases', 'custody', 'files']
  if (!kinds.includes(value)) throw new BadRequestError(`kind must be one of ${kinds.join(', ')}`)
  return value as BackupKind
}

/**
 * A byte count from the wire.
 *
 * A STRING, not a JSON number, and parsed to `bigint`. The ceiling is up to 1 TiB — 2^40 — which is
 * inside `Number.MAX_SAFE_INTEGER`, so this is not yet a precision bug. It is written as a bigint
 * anyway because the day somebody raises the ceiling to a petabyte is the day a silent rounding in
 * a disk-space guard starts letting writes through that should have been refused, and that failure
 * would look exactly like the guard working.
 */
function parseByteCount(value: string, field: string): bigint {
  if (!/^\d{1,20}$/.test(value)) {
    throw new BadRequestError(`${field} must be a decimal string of bytes`)
  }
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
    if (size > MAX_BODY_BYTES) throw new BodyTooLargeError()
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
  // An abandoned request body leaves unread bytes in the socket, so the connection cannot be
  // reused — the next request on it would be parsed from the middle of the discarded body. The
  // response is written FIRST and the socket destroyed only once it has flushed, or the caller
  // gets a reset instead of the 400 that explains what they did wrong. See `BodyTooLargeError`.
  res.end(payload, () => {
    if (headers['connection'] === 'close') res.socket?.destroy()
  })
}
