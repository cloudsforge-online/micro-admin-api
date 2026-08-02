/**
 * The upstream clients.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **EVERY ROUTE BELOW WAS READ IN THE PROVIDER'S SOURCE AND IS CITED BY path:line.**
 *
 * 18-build-status.md records six occasions in this estate where a client was built against an
 * imagined surface, one of which returned 403 on every marketplace listing, and one of which is
 * still live: `wallet/src/pricingclient.ts` calls `GET /v1/quotes`, which pricing does not serve.
 * So each method here names the route table entry it calls, the guard on it, and the scope or role
 * that guard demands. A citation that stops being true is a compile-time-invisible defect, which
 * is why `upstreams.test.ts` also asserts the shape of every request this file builds.
 *
 *   ledger   POST /entries/:id/reverse        ledger/src/server.ts:394
 *            guard: authorise(POST_SCOPE)     ledger/src/server.ts:78 → 'ledger:post'
 *            SERVICE TOKEN ONLY               ledger/src/server.ts:~250 `authorise` refuses a
 *                                             user principal outright
 *   ledger   GET  /trial-balance              ledger/src/server.ts:513, scope 'ledger:read'
 *   ledger   POST /entries                    ledger/src/server.ts:346, scope 'ledger:post' —
 *                                             body shape from parsePostEntry at :646-707
 *   ledger   GET  /accounts/:subject/balances ledger/src/server.ts:499, scope 'ledger:read'
 *   market   POST /v1/moderation/cases/:id/resolve   market/src/server.ts:1086
 *            guard: requireOperator           market/src/server.ts:~1155 — a SERVICE token needs
 *                                             'market:admin', a USER token needs role:admin
 *   market   GET  /v1/moderation/cases        market/src/server.ts:1051, same guard
 *   billing  POST /entitlements/:id/revoke    billing/src/server.ts:544
 *            guard: 'billing:grant' for a service, role:admin for a user
 *   any      GET  /readyz                     rule 4 of docs/ecosystem/03 §2 — universal
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **WHICH CREDENTIAL EACH CALL CARRIES, AND WHY THE ANSWER IS NOT UNIFORM.**
 *
 * SD-11 records something the frozen estate got right: "Nimbus's admin proxies forward the
 * operator's own bearer token rather than a service secret, which is a genuinely good decision:
 * Pay and custody record *which* administrator acted." That is preserved here — but only where
 * the upstream can accept it.
 *
 *   market, billing   THE OPERATOR'S OWN BEARER. Both guards admit a user token with `role:admin`,
 *                     so market records `resolvedBy: <the operator's user id>` and billing records
 *                     `actor: user:<id>`. The upstream's audit names the human, not this service.
 *
 *   ledger            THIS SERVICE'S SCOPED SERVICE TOKEN, because `authorise` refuses a user
 *                     principal outright and there is no route that does otherwise. The ledger
 *                     therefore records `service:admin-api` as the actor. The human is not lost:
 *                     the entry's `metadata.operator` names them, this service's hash-chained
 *                     audit row names them, and both carry the same `correlationId`. This is
 *                     stated rather than hidden because it is the one place in this service where
 *                     an upstream's record of "who" is less specific than ours, and an operator
 *                     reading the ledger alone should know to come back here for the name.
 *
 * There is no route on this service that takes a `userId` as a parameter and acts for it. The
 * frozen estate's `/internal` routes did, `deploy/gateway/dynamic/policy.yml` refuses them from
 * outside for that reason, and nothing here is an equivalent: the caller of every method below is
 * an authenticated operator, and the operation names a ledger entry, a moderation case or an
 * entitlement — never "whoever this user is".
 */

import { HttpClient, HttpError, type ResultEvent } from '@cloudsforge/http'

/** An upstream refused, or could not be reached. Distinguished, because they mean different things. */
export class UpstreamError extends Error {
  readonly upstream: string
  readonly status: number | null
  /** True when the peer answered with a 4xx: it decided, and retrying produces the same answer. */
  readonly peerDecided: boolean
  constructor(upstream: string, message: string, status: number | null, peerDecided: boolean) {
    super(message)
    this.name = 'UpstreamError'
    this.upstream = upstream
    this.status = status
    this.peerDecided = peerDecided
  }
}

function wrap(upstream: string, err: unknown): UpstreamError {
  if (err instanceof HttpError) {
    // The body is NOT propagated into the message. An upstream's error body can carry a subject's
    // email or a listing's private terms, and this service's errors are read by an operator
    // console and written into logs that a wider audience sees than the upstream's own.
    return new UpstreamError(upstream, `${upstream} answered ${err.status}`, err.status, err.peerDecided)
  }
  return new UpstreamError(upstream, `${upstream} could not be reached`, null, false)
}

export interface ClientConfig {
  readonly baseUrl: string
  readonly deadlineMs: number
  /** This service's own scoped service token. Used only where a user token is refused. */
  readonly serviceToken: () => string
  readonly fetch?: typeof globalThis.fetch
  readonly onResult?: (event: ResultEvent) => void
}

function clientFor(name: string, config: ClientConfig): HttpClient {
  return new HttpClient({
    baseUrl: config.baseUrl,
    name,
    defaultDeadlineMs: config.deadlineMs,
    ...(config.fetch ? { fetch: config.fetch } : {}),
    ...(config.onResult ? { onResult: config.onResult } : {}),
  })
}

/**
 * A bearer to present. Either this service's own credential or an operator's, made explicit at
 * every call site so the choice is never a default somebody inherited.
 */
export type Credential = { readonly kind: 'service' } | { readonly kind: 'operator'; readonly bearer: string }

function authHeader(config: ClientConfig, credential: Credential): Record<string, string> {
  const token = credential.kind === 'service' ? config.serviceToken() : credential.bearer
  return { authorization: `Bearer ${token}` }
}

/* ------------------------------------------------------------------------ readiness */

export interface ReadinessSnapshot {
  readonly ready: boolean
  readonly state: string
  readonly detail: string | null
}

/**
 * Read one upstream's `/readyz`.
 *
 * A 503 is an ANSWER, not a failure: `/readyz` returning 503 is the endpoint working correctly on
 * a service that is not ready. So a 503 with a readable body resolves rather than throws, and only
 * an unreachable peer or an unparseable answer becomes an `UpstreamError`. Getting this backwards
 * is how an operator console shows "unknown" for a service that is clearly and correctly telling
 * everyone it is unwell.
 */
export async function probeReadiness(
  name: string,
  config: ClientConfig,
  signal?: AbortSignal,
): Promise<ReadinessSnapshot> {
  const doFetch = config.fetch ?? globalThis.fetch
  const url = `${config.baseUrl.replace(/\/+$/, '')}/readyz`
  const timeout = AbortSignal.timeout(config.deadlineMs)
  const combined = signal ? AbortSignal.any([signal, timeout]) : timeout
  let response: Response
  try {
    response = await doFetch(url, { signal: combined, redirect: 'manual' })
  } catch {
    throw new UpstreamError(name, `${name} could not be reached`, null, false)
  }
  const text = await response.text().catch(() => '')
  let body: Record<string, unknown> = {}
  try {
    body = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {}
  } catch {
    // A readiness endpoint that answers something other than JSON is a readiness endpoint whose
    // answer we cannot use, whatever its status code was.
    throw new UpstreamError(name, `${name} answered /readyz with a body that is not JSON`, response.status, true)
  }
  const failed = Array.isArray(body['checks'])
    ? (body['checks'] as Array<Record<string, unknown>>)
        .filter((c) => c['state'] !== 'pass')
        .map((c) => String(c['name'] ?? 'unnamed'))
    : []
  return {
    ready: body['ready'] === true,
    state: typeof body['state'] === 'string' ? body['state'] : response.ok ? 'ready' : 'unknown',
    detail: failed.length > 0 ? `failing checks: ${failed.join(', ')}` : null,
  }
}

/* ------------------------------------------------------------------------ ledger */

export interface ReverseEntryRequest {
  readonly entryId: string
  readonly idempotencyKey: string
  readonly description: string
  readonly correlationId: string
  /** The operator whose approval authorised this. Carried in metadata; see the file header. */
  readonly operator: string
  readonly approvalId: string
}

export interface ReversedEntry {
  readonly id: string
  readonly reversesEntryId: string | null
  readonly replayed: boolean
}

export interface TrialBalance {
  readonly balanced: boolean
  readonly totalAbsoluteDelta: string
}

/**
 * One side of an entry this service posts. Field names are the ledger's, read from
 * `parsePostEntry` at ledger/src/server.ts:646-707: `direction`, `amount` (a DECIMAL STRING —
 * a JSON number near an 18-decimal amount comes back subtly wrong, not visibly broken),
 * `assetCode`, `sequence`, and an inline `account` block, which is what makes the engagement
 * accounts' creation idempotent on first use: the ledger's `ensureAccount`
 * (ledger/src/accounts.ts:100) is `on conflict do nothing` on the account key.
 */
export interface EntryPosting {
  readonly direction: 'debit' | 'credit'
  readonly amount: string
  readonly assetCode: string
  readonly sequence: number
  readonly account: {
    readonly subject: string
    readonly assetCode: string
    readonly purpose: string
    readonly type: string
  }
}

export interface PostEntryRequest {
  /** One of the ledger's closed `journal_entries_kind_chk` list — ledger/src/migrations.ts:180. */
  readonly kind: string
  readonly idempotencyKey: string
  readonly description: string
  readonly correlationId: string
  readonly postings: readonly EntryPosting[]
  /** The operator whose approval authorised this. Carried in metadata; see the file header. */
  readonly operator: string
  readonly approvalId: string
}

export interface PostedEntry {
  readonly id: string
  readonly replayed: boolean
}

export interface AccountBalance {
  readonly subject: string
  readonly assetCode: string
  readonly purpose: string
  readonly type: string
  readonly status: string
  /** A decimal string in the account's normal direction — ledger/src/accounts.ts:160-172. */
  readonly amount: string
}

export interface LedgerClient {
  /** `POST /entries/:id/reverse` — ledger/src/server.ts:394, scope `ledger:post`. */
  reverseEntry(request: ReverseEntryRequest): Promise<ReversedEntry>
  /** `POST /entries` — ledger/src/server.ts:346, scope `ledger:post`. SERVICE TOKEN ONLY. */
  postEntry(request: PostEntryRequest): Promise<PostedEntry>
  /** `GET /trial-balance` — ledger/src/server.ts:513, scope `ledger:read`. */
  trialBalance(): Promise<TrialBalance>
  /** `GET /accounts/:subject/balances` — ledger/src/server.ts:499, scope `ledger:read`. */
  balancesForSubject(subject: string): Promise<readonly AccountBalance[]>
}

export function httpLedgerClient(config: ClientConfig): LedgerClient {
  const client = clientFor('ledger', config)
  return {
    async reverseEntry(request) {
      try {
        // The body's field names are the ledger's, read from its handler at server.ts:394-419:
        // originatingService, actor, correlationId, idempotencyKey, description, kind, metadata.
        // `actor` is typed `service:${string}` there, which is why the operator travels in
        // metadata rather than in the field whose name suggests it.
        const answer = await client.post<{ entry: ReversedEntry; replayed: boolean }>(
          `/entries/${encodeURIComponent(request.entryId)}/reverse`,
          {
            originatingService: 'admin-api',
            actor: 'service:admin-api',
            correlationId: request.correlationId,
            idempotencyKey: request.idempotencyKey,
            description: request.description,
            metadata: {
              operator: request.operator,
              approvalId: request.approvalId,
              // Named so an auditor reading the ledger alone knows where the human is recorded.
              operatorRecordedIn: 'admin-api audit_events',
            },
          },
          { idempotencyKey: request.idempotencyKey, requestId: request.correlationId, headers: authHeader(config, { kind: 'service' }) },
        )
        return { ...answer.entry, replayed: answer.replayed }
      } catch (err) {
        throw wrap('ledger', err)
      }
    },
    async postEntry(request) {
      try {
        // Body fields from `parsePostEntry`, ledger/src/server.ts:646-707. `actor` is typed
        // `service:${string}` there, so — exactly as in reverseEntry above — the human operator
        // travels in metadata and in this service's hash-chained audit row, joined by the
        // correlation id.
        const answer = await client.post<{ entry: { id: string }; replayed: boolean }>(
          '/entries',
          {
            kind: request.kind,
            originatingService: 'admin-api',
            actor: 'service:admin-api',
            correlationId: request.correlationId,
            idempotencyKey: request.idempotencyKey,
            description: request.description,
            postings: request.postings,
            metadata: {
              operator: request.operator,
              approvalId: request.approvalId,
              operatorRecordedIn: 'admin-api audit_events',
            },
          },
          {
            idempotencyKey: request.idempotencyKey,
            requestId: request.correlationId,
            headers: authHeader(config, { kind: 'service' }),
          },
        )
        return { id: answer.entry.id, replayed: answer.replayed }
      } catch (err) {
        throw wrap('ledger', err)
      }
    },
    async trialBalance() {
      try {
        return await client.get<TrialBalance>('/trial-balance', {
          headers: authHeader(config, { kind: 'service' }),
        })
      } catch (err) {
        throw wrap('ledger', err)
      }
    },
    async balancesForSubject(subject) {
      try {
        // The subject is `platform:engagement-treasury` or `engagement:<service>` — both carry a
        // colon, and the route decodes (`decodeURIComponent`, ledger/src/server.ts:503), so the
        // encoding here is what a well-behaved client owes it.
        const answer = await client.get<{ balances: readonly AccountBalance[] }>(
          `/accounts/${encodeURIComponent(subject)}/balances`,
          { headers: authHeader(config, { kind: 'service' }) },
        )
        return answer.balances ?? []
      } catch (err) {
        throw wrap('ledger', err)
      }
    },
  }
}

/* ------------------------------------------------------------------------ market */

export interface ResolveCaseRequest {
  readonly caseId: string
  readonly state: 'upheld' | 'dismissed'
  readonly notes: string
  readonly correlationId: string
  /** Forwarded verbatim, so market records which administrator resolved the case. */
  readonly operatorBearer: string
}

export interface ModerationCase {
  readonly id: string
  readonly state: string
  readonly subjectUrn?: string
}

export interface MarketClient {
  /** `POST /v1/moderation/cases/:id/resolve` — market/src/server.ts:1086. */
  resolveCase(request: ResolveCaseRequest): Promise<ModerationCase>
  /** `GET /v1/moderation/cases?state=open` — market/src/server.ts:1051. */
  openCases(operatorBearer: string): Promise<readonly ModerationCase[]>
}

export function httpMarketClient(config: ClientConfig): MarketClient {
  const client = clientFor('market', config)
  return {
    async resolveCase(request) {
      try {
        // Body fields read from market/src/server.ts:1089-1099: `state` must be 'upheld' or
        // 'dismissed', `notes` is optional. `resolvedBy` is NOT a body field — market derives it
        // from the principal, which is exactly why the operator's bearer is forwarded.
        const answer = await client.post<{ case: ModerationCase }>(
          `/v1/moderation/cases/${encodeURIComponent(request.caseId)}/resolve`,
          { state: request.state, notes: request.notes },
          {
            requestId: request.correlationId,
            headers: authHeader(config, { kind: 'operator', bearer: request.operatorBearer }),
          },
        )
        return answer.case
      } catch (err) {
        throw wrap('market', err)
      }
    },
    async openCases(operatorBearer) {
      try {
        const answer = await client.get<{ cases: readonly ModerationCase[] }>(
          '/v1/moderation/cases?state=open',
          { headers: authHeader(config, { kind: 'operator', bearer: operatorBearer }) },
        )
        return answer.cases ?? []
      } catch (err) {
        throw wrap('market', err)
      }
    },
  }
}

/* ------------------------------------------------------------------------ billing */

export interface RevokeEntitlementRequest {
  readonly entitlementId: string
  readonly reason: string
  readonly refund: boolean
  readonly correlationId: string
  readonly operatorBearer: string
}

export interface RevokeResult {
  readonly alreadyRevoked: boolean
  readonly reversalEntryId?: string | null
}

export interface BillingClient {
  /** `POST /entitlements/:id/revoke` — billing/src/server.ts:544. */
  revokeEntitlement(request: RevokeEntitlementRequest): Promise<RevokeResult>
}

export function httpBillingClient(config: ClientConfig): BillingClient {
  const client = clientFor('billing', config)
  return {
    async revokeEntitlement(request) {
      try {
        // Body fields read from billing/src/server.ts:548-551: `reason` is required and must be
        // non-empty, `refund` is a boolean. `actor` is derived from the principal there
        // (`actorOf`), so forwarding the operator's bearer is what makes billing's own audit name
        // the human rather than this service.
        return await client.post<RevokeResult>(
          `/entitlements/${encodeURIComponent(request.entitlementId)}/revoke`,
          { reason: request.reason, refund: request.refund },
          {
            requestId: request.correlationId,
            headers: authHeader(config, { kind: 'operator', bearer: request.operatorBearer }),
          },
        )
      } catch (err) {
        throw wrap('billing', err)
      }
    },
  }
}
