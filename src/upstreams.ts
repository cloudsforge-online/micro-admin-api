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
 *   ledger   POST /entries/:id/reverse        ledger/src/server.ts
 *            guard: authorise(POST_SCOPE)     ledger/src/server.ts → 'ledger:post'
 *            SERVICE TOKEN ONLY               ledger/src/server.ts:~250 `authorise` refuses a
 *                                             user principal outright
 *   ledger   GET  /trial-balance              ledger/src/server.ts, scope 'ledger:read'
 *   ledger   POST /entries                    ledger/src/server.ts, scope 'ledger:post' —
 *                                             body shape from parsePostEntry at :646-707
 *   ledger   GET  /accounts/:subject/balances ledger/src/server.ts, scope 'ledger:read'
 *   market   POST /v1/moderation/cases/:id/resolve   market/src/server.ts
 *            guard: requireOperator           market/src/server.ts:~1155 — a SERVICE token needs
 *                                             'market:admin', a USER token needs role:admin
 *   market   GET  /v1/moderation/cases        market/src/server.ts, same guard
 *   billing  POST /entitlements/:id/revoke    billing/src/server.ts
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
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE SERVICE BEARER IS NOW EXCHANGED, NOT PRESENTED — micro-org #222.**
 *
 * `serviceToken` below used to be `() => string`, and `index.ts` filled it with
 * `() => env.serviceToken`: one string, read once at import, put verbatim in the `authorization`
 * header of every call this file marks `{ kind: 'service' }`. Measured on the live estate on
 * 2026-08-05, that string was a 701-byte JWT that had **expired 26 hours earlier** on a container
 * reporting healthy — so every ledger reversal, every trial-balance read and every role grant this
 * service attempted for a day came back 401, and `/livez` never noticed because it makes no
 * outbound call.
 *
 * That is the ten-minute cliff (#197), and it is not a shape a longer expiry can fix. `settlement`
 * read a 600-second token once at boot (`settlement/src/index.ts`), authenticated for ten
 * minutes after each restart, was dead thereafter, and produced **1,315 undelivered withdrawal
 * attempts** against a treasury that read as empty. A longer-lived JWT would have moved that cliff,
 * not removed it.
 *
 * So `serviceToken` is `() => Promise<string>` — async because the value is now MINTED rather than
 * read, and a function because it must be able to differ between two calls a minute apart. See
 * `buildUpstreams` at the foot of this file for who fills it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { HttpClient, HttpError, NETWORK_HEADER, type Network, type ResultEvent } from '@cloudsforge/http'
import {
  ServiceTokenProvider,
  ServiceTokenUnavailableError,
  type ProviderEvent,
} from '@cloudsforge/auth'
import type { EntryKind } from '@cloudsforge/contracts-money'
// TYPE-ONLY, and that matters. `./env.ts` validates the process environment at import and calls
// `process.exit(1)` when it is incomplete, so a value import here would make this module — and
// therefore every test of the wiring in it — impossible to load without a full environment. That
// is the same "untestable therefore unchecked" property that let the cliff survive.
import type { Env } from './env.ts'

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
  /**
   * The estate every call from this client belongs to, sent as `CF-Network`.
   *
   * Undefined in a single-network deployment, and then no header is sent at all — which is what
   * makes this change invisible until the consolidation reaches the peer. See micro-deploy
   * `docs/network-consolidation.md`.
   */
  readonly network?: Network
  /**
   * This service's own scoped service bearer, MINTED per call. Used only where a user token is
   * refused.
   *
   * Async and a function, because what it returns is a short-lived token exchanged from a
   * long-lived credential and re-minted before expiry. It **rejects** rather than resolving
   * `undefined` when this process cannot authenticate — see `buildUpstreams`.
   */
  readonly serviceToken: () => Promise<string>
  readonly fetch?: typeof globalThis.fetch
  readonly onResult?: (event: ResultEvent) => void
}

function clientFor(name: string, config: ClientConfig): HttpClient {
  return new HttpClient({
    baseUrl: config.baseUrl,
    name,
    defaultDeadlineMs: config.deadlineMs,
    // ── THE ESTATE THIS CLIENT SPEAKS FOR ────────────────────────────────────────────────────
    //
    // A client-wide header rather than a per-call argument, because admin-api's peer interfaces
    // are domain methods (`trialBalance()`, `reverseEntry(request)`) with nowhere to put one, and
    // threading an options bag through twenty of them would leave nineteen right and one wrong.
    //
    // One client set per network is built at boot instead. There is no circuit state on these
    // clients to split, and `RequestOptions.network` still beats this bag if a call ever needs to
    // override it — the precedence `@cloudsforge/http` documents.
    //
    // Omitted when unset, which is what keeps a single-network deployment byte-identical.
    ...(config.network ? { headers: { [NETWORK_HEADER]: config.network } } : {}),
    ...(config.fetch ? { fetch: config.fetch } : {}),
    ...(config.onResult ? { onResult: config.onResult } : {}),
  })
}

/**
 * A bearer to present. Either this service's own credential or an operator's, made explicit at
 * every call site so the choice is never a default somebody inherited.
 */
export type Credential = { readonly kind: 'service' } | { readonly kind: 'operator'; readonly bearer: string }

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * WHAT THIS SERVICE'S SERVICE TOKEN MUST CARRY, DECLARED WHERE THE CALL SITES ARE — micro-org #317
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * These four constants are not read by anything inside this repository at runtime. They are read
 * by `deploy/scripts/derive-grants.mjs`, which walks every service's `src` for modules that
 * construct an `HttpClient` and name a bearer, and BUILDS `IDENTITY_SERVICE_TOKEN_GRANTS` — the
 * map identity mints from — out of their exported `*_SCOPES`. Declaring here is what makes the
 * estate's copy a derivative of this file rather than a second opinion about it.
 *
 * **WHY THIS FILE WAS ONE OF THE HOLDOUTS, AND WHAT IT COST.** Until now `admin-api/src/upstreams.ts`
 * was a hand-written entry in `deploy/compose/estate/grant-gaps.json`: a module micro-deploy knew
 * presented a credential and could not read a demand from, so somebody in another repository wrote
 * this service's authority down for it. That is the arrangement that produced the boxed claim in
 * `actions.ts` — read it, it is the headline of #317 — asserting for months that this service's
 * token lacked `identity:admin` and held `market:read`, `market:admin` and `billing:read`. Measured
 * against `cloudsforge-estate-identity-1` on 2026-08-10 the real entry was
 * `["identity:admin","ledger:post","ledger:read"]`: the scope said to be missing was present, and
 * three of the four said to be present did not exist. Nobody was careless. A fact copied into a
 * repository that cannot verify it has no mechanism to stay true, and the copy that rots is
 * always the one furthest from the call site.
 *
 * So the demand is asserted from the module that makes the calls, and the assertion has teeth:
 * `upstreams.test.ts` walks the source of this file and fails if a `{ kind: 'service' }` call site
 * appears in a client whose constant says it needs nothing. A future method that quietly starts
 * presenting the service bearer cannot slip past the declaration and re-open the same gap.
 *
 * **THE EMPTY ONES ARE DECLARATIONS, NOT OMISSIONS.** `market` and `billing` forward the OPERATOR'S
 * OWN bearer — see the file header — so no scope on this service's token makes those calls
 * stronger, and granting one would be a live capability on a live token that nothing consults.
 * `derive-grants.mjs` reads a bare `Object.freeze([])` as exactly that statement and, since it does,
 * a gaps entry for this file is now stale and fails. Deleting it is micro-deploy's, and it is named
 * in #317's closing comment rather than done from here.
 *
 * `derive-grants.mjs` prefers `NO_SCOPES_REQUIRED` from `@cloudsforge/contracts-auth` for the empty
 * form, and it is the better spelling. It is not used here because this repository deliberately
 * depends on runtime `@cloudsforge/auth` and not on contracts-auth — `scopes.ts` explains why at
 * length — and taking on a package dependency to change how an empty list is spelled is a larger
 * decision than this declaration is. The two are identical at runtime and both are read.
 */

/** `reverse`, `postEntry`, `trialBalance` and `balances`, all `{ kind: 'service' }`. */
export const LEDGER_SCOPES: readonly string[] = Object.freeze(['ledger:post', 'ledger:read'])

/** `setRoles` → `PUT /internal/users/:id/roles`, which identity refuses to any non-service principal. */
export const IDENTITY_SCOPES: readonly string[] = Object.freeze(['identity:admin'])

/** Nothing: `resolveCase` and `listCases` present the operator's bearer, per SD-11. */
export const MARKET_SCOPES: readonly string[] = Object.freeze([])

/** Nothing: `revokeEntitlement` presents the operator's bearer, per SD-11. */
export const BILLING_SCOPES: readonly string[] = Object.freeze([])

/**
 * ASYNC, and the `await` at each of the eight call sites is the fix rather than a cost.
 *
 * A synchronous `authHeader` could only ever return a string somebody already held, which is
 * precisely the seam that let a dead JWT be presented for 26 hours. Minting happens here, at the
 * moment the header is built, so a token that expired between two operator actions is replaced
 * before it is sent rather than discovered by the peer.
 *
 * The operator branch stays untouched and stays sync in spirit: an operator's bearer is theirs,
 * arrives on the inbound request, and is nothing this service may mint, refresh or substitute.
 */
async function authHeader(
  config: ClientConfig,
  credential: Credential,
): Promise<Record<string, string>> {
  const token = credential.kind === 'service' ? await config.serviceToken() : credential.bearer
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
 * `parsePostEntry` at ledger/src/server.ts: `direction`, `amount` (a DECIMAL STRING —
 * a JSON number near an 18-decimal amount comes back subtly wrong, not visibly broken),
 * `assetCode`, `sequence`, and an inline `account` block, which is what makes the engagement
 * accounts' creation idempotent on first use: the ledger's `ensureAccount`
 * (ledger/src/accounts.ts) is `on conflict do nothing` on the account key.
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
  /**
   * `EntryKind` — `ENTRY_KINDS` in `@cloudsforge/contracts-money` — and not `string`, because the
   * ledger's vocabulary is closed and a kind outside it is refused rather than recorded:
   * `validateEntryRequest` answers `400 invalid_entry` before it opens a transaction, and
   * `journal_entries_kind_chk` refuses it again behind that. Two services shipped an invented kind
   * and the symptom each time was nothing happening — `micro-foresight` posted
   * `foresight.settlement_fee` for months and no settlement fee was ever booked, and
   * `micro-tessera` posted `item_issue` while the set did not yet contain it, so no object ever
   * entered the ledger (micro-org#407 §3). Neither is a mistake a `string` here can catch, and an
   * absence is the one failure nobody goes looking for; typed, an invented kind does not compile.
   */
  readonly kind: EntryKind
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
  /** A decimal string in the account's normal direction — ledger/src/accounts.ts. */
  readonly amount: string
}

export interface LedgerClient {
  /** `POST /entries/:id/reverse` — ledger/src/server.ts, scope `ledger:post`. */
  reverseEntry(request: ReverseEntryRequest): Promise<ReversedEntry>
  /** `POST /entries` — ledger/src/server.ts, scope `ledger:post`. SERVICE TOKEN ONLY. */
  postEntry(request: PostEntryRequest): Promise<PostedEntry>
  /** `GET /trial-balance` — ledger/src/server.ts, scope `ledger:read`. */
  trialBalance(): Promise<TrialBalance>
  /** `GET /accounts/:subject/balances` — ledger/src/server.ts, scope `ledger:read`. */
  balancesForSubject(subject: string): Promise<readonly AccountBalance[]>
}

export function httpLedgerClient(config: ClientConfig): LedgerClient {
  const client = clientFor('ledger', config)
  return {
    async reverseEntry(request) {
      try {
        // The body's field names are the ledger's, read from its handler at server.ts:
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
          { idempotencyKey: request.idempotencyKey, requestId: request.correlationId, headers: await authHeader(config, { kind: 'service' }) },
        )
        return { ...answer.entry, replayed: answer.replayed }
      } catch (err) {
        throw wrap('ledger', err)
      }
    },
    async postEntry(request) {
      try {
        // Body fields from `parsePostEntry`, ledger/src/server.ts. `actor` is typed
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
            headers: await authHeader(config, { kind: 'service' }),
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
          headers: await authHeader(config, { kind: 'service' }),
        })
      } catch (err) {
        throw wrap('ledger', err)
      }
    },
    async balancesForSubject(subject) {
      try {
        // The subject is `platform:engagement-treasury` or `engagement:<service>` — both carry a
        // colon, and the route decodes (`decodeURIComponent`, ledger/src/server.ts), so the
        // encoding here is what a well-behaved client owes it.
        const answer = await client.get<{ balances: readonly AccountBalance[] }>(
          `/accounts/${encodeURIComponent(subject)}/balances`,
          { headers: await authHeader(config, { kind: 'service' }) },
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
  /** `POST /v1/moderation/cases/:id/resolve` — market/src/server.ts. */
  resolveCase(request: ResolveCaseRequest): Promise<ModerationCase>
  /** `GET /v1/moderation/cases?state=open` — market/src/server.ts. */
  openCases(operatorBearer: string): Promise<readonly ModerationCase[]>
}

export function httpMarketClient(config: ClientConfig): MarketClient {
  const client = clientFor('market', config)
  return {
    async resolveCase(request) {
      try {
        // Body fields read from market/src/server.ts: `state` must be 'upheld' or
        // 'dismissed', `notes` is optional. `resolvedBy` is NOT a body field — market derives it
        // from the principal, which is exactly why the operator's bearer is forwarded.
        const answer = await client.post<{ case: ModerationCase }>(
          `/v1/moderation/cases/${encodeURIComponent(request.caseId)}/resolve`,
          { state: request.state, notes: request.notes },
          {
            requestId: request.correlationId,
            headers: await authHeader(config, { kind: 'operator', bearer: request.operatorBearer }),
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
          { headers: await authHeader(config, { kind: 'operator', bearer: operatorBearer }) },
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
  /** `POST /entitlements/:id/revoke` — billing/src/server.ts. */
  revokeEntitlement(request: RevokeEntitlementRequest): Promise<RevokeResult>
}

export function httpBillingClient(config: ClientConfig): BillingClient {
  const client = clientFor('billing', config)
  return {
    async revokeEntitlement(request) {
      try {
        // Body fields read from billing/src/server.ts: `reason` is required and must be
        // non-empty, `refund` is a boolean. `actor` is derived from the principal there
        // (`actorOf`), so forwarding the operator's bearer is what makes billing's own audit name
        // the human rather than this service.
        return await client.post<RevokeResult>(
          `/entitlements/${encodeURIComponent(request.entitlementId)}/revoke`,
          { reason: request.reason, refund: request.refund },
          {
            requestId: request.correlationId,
            headers: await authHeader(config, { kind: 'operator', bearer: request.operatorBearer }),
          },
        )
      } catch (err) {
        throw wrap('billing', err)
      }
    },
  }
}

/* ------------------------------------------------------------------------ nda */

/**
 * Ninety Days After — the game service behind Forge Worlds.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THIS IS A PROXY AND NOT A DIRECT CALL FROM THE CONSOLE.**
 *
 * The Foresight panel in `admin-web` calls Foresight DIRECTLY on `foresight.<apex>`, because that
 * surface has a hostname: a Cloudflare DNS record, a tunnel ingress rule, an Access policy and a
 * pair of Traefik routers. `nda` has none of those. `cloudsforge-estate-nda-1` has been healthy for
 * weeks and is unreachable from any browser on earth, which is the whole reason the title has never
 * left `draft` — not a missing feature, a missing door.
 *
 * Publishing `nda.<apex>` would mean creating that DNS record and its Access policy by hand in
 * Cloudflare, which no repository can do and no test can check. Proxying costs one env var and
 * reaches the same service over the compose network today. See `deploy/cloudflared/config.*.yml`
 * for the enumeration this deliberately does not have to join.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **THE OPERATOR'S OWN BEARER, LIKE MARKET AND BILLING.** `nda/src/server.ts` guards every mutation
 * below with `requireAdminPrincipal`, which admits EITHER a service holding `nda:write` OR a user
 * with `role:admin` — so forwarding the human's token makes nda's own outbox events name the
 * administrator who generated the world rather than this service. That is SD-11, and it is also why
 * `NDA_SCOPES` is empty: minting `nda:write` onto this service's token would be a live capability
 * that nothing here consults.
 *
 *   nda  GET  /v1/worlds              nda/src/server.ts:543   guard: requirePrincipal (any user)
 *   nda  POST /v1/worlds              nda/src/server.ts:709   guard: requireAdminPrincipal
 *   nda  POST /v1/worlds/:id/start    nda/src/server.ts:731   guard: requireAdminPrincipal
 *   nda  PUT  /v1/worlds/:id/bots     nda/src/server.ts:744   guard: requireAdminPrincipal
 *   nda  POST /v1/worlds/:id/tick     nda/src/server.ts:768   guard: requireAdminPrincipal
 *
 * **EVERY MUTATION CARRIES AN `Idempotency-Key`, AND IT IS A PARAMETER RATHER THAN A DEFAULT.**
 * `defineMutation(..., 'header', ...)` in nda means the header is REQUIRED — a call without one is
 * refused, not accepted unsafely. Defaulting it to this request's id here would satisfy nda and
 * defeat it: generating a fresh world map is expensive and a double-submit would build two. The
 * console mints one key per submission attempt and resends it on retry, so nda answers the second
 * attempt with `replayed: true` and the same world.
 */

/** `lobby` before it starts, `active` while days resolve, `archived` when the season ends. */
export type WorldStatus = 'lobby' | 'active' | 'archived'

/** `WorldSnapshot` from nda/src/engine/state.ts, plus the counts nda's list route folds in. */
export interface WorldSummary {
  readonly id: string
  readonly name: string
  readonly seed: string
  readonly status: WorldStatus
  /** The day already resolved. Resolution produces `day + 1`. */
  readonly day: number
  readonly seasonLength: number
  readonly width: number
  readonly height: number
  readonly tickIntervalMinutes: number
  readonly humans: number
  readonly bots: number
}

export interface CreateWorldRequest {
  readonly name: string
  /** Omitted fields take nda's own defaults (`WORLD_DEFAULTS`), which is why they are optional. */
  readonly width?: number | undefined
  readonly height?: number | undefined
  readonly seasonLength?: number | undefined
  readonly tickIntervalMinutes?: number | undefined
  /** Omitted means nda seeds the map from the new world's id, as the frozen ancestor did. */
  readonly seed?: string | undefined
  readonly idempotencyKey: string
  readonly correlationId: string
  readonly operatorBearer: string
}

export interface WorldMutationRequest {
  readonly worldId: string
  readonly idempotencyKey: string
  readonly correlationId: string
  readonly operatorBearer: string
}

export interface SetBotsRequest extends WorldMutationRequest {
  readonly enabled: boolean
  /** Ignored by nda when `enabled` is false — it syncs to zero. 0..200. */
  readonly count: number
}

export interface NdaClient {
  /** `GET /v1/worlds?status=…` — nda/src/server.ts:543. */
  listWorlds(request: {
    readonly statuses: readonly WorldStatus[]
    readonly correlationId: string
    readonly operatorBearer: string
  }): Promise<readonly WorldSummary[]>
  /** `POST /v1/worlds` — nda/src/server.ts:709. 201 fresh, 200 replayed. */
  createWorld(request: CreateWorldRequest): Promise<{ world: WorldSummary; replayed: boolean }>
  /** `POST /v1/worlds/:id/start` — nda/src/server.ts:731. */
  startWorld(request: WorldMutationRequest): Promise<{ world: WorldSummary; replayed: boolean }>
  /** `PUT /v1/worlds/:id/bots` — nda/src/server.ts:744. */
  setBots(request: SetBotsRequest): Promise<{ bots: number; replayed: boolean }>
  /** `POST /v1/worlds/:id/tick` — nda/src/server.ts:768. 202: it ENQUEUES, it does not resolve. */
  tickWorld(request: WorldMutationRequest): Promise<{ queued: boolean; replayed: boolean }>
}

/** Nothing: every method presents the OPERATOR's bearer, which `requireAdminPrincipal` admits. */
export const NDA_SCOPES: readonly string[] = Object.freeze([])

export function httpNdaClient(config: ClientConfig): NdaClient {
  const client = clientFor('nda', config)
  /** The operator's own token plus the key nda's `defineMutation` requires. */
  const mutationHeaders = async (request: {
    readonly idempotencyKey: string
    readonly operatorBearer: string
  }): Promise<Record<string, string>> => ({
    ...(await authHeader(config, { kind: 'operator', bearer: request.operatorBearer })),
    'idempotency-key': request.idempotencyKey,
  })

  return {
    async listWorlds(request) {
      try {
        // nda defaults an ABSENT `status` to `lobby,active` — archived seasons are excluded. The
        // console asks for all three by name, because an operator's question here is "what have we
        // ever generated", and a world that has finished its season is the interesting one.
        const query =
          request.statuses.length > 0
            ? `?status=${encodeURIComponent(request.statuses.join(','))}`
            : ''
        const answer = await client.get<{ worlds: readonly WorldSummary[] }>(`/v1/worlds${query}`, {
          requestId: request.correlationId,
          headers: await authHeader(config, { kind: 'operator', bearer: request.operatorBearer }),
        })
        return answer.worlds ?? []
      } catch (err) {
        throw wrap('nda', err)
      }
    },
    async createWorld(request) {
      try {
        // Body fields read from nda/src/server.ts:709. `name` is required; the four numbers and
        // `seed` are OMITTED rather than sent as null when absent, because nda's `optionalInt`
        // spreads a present key and a null would fail its integer bound rather than take the
        // default.
        return await client.post<{ world: WorldSummary; replayed: boolean }>(
          '/v1/worlds',
          {
            name: request.name,
            ...(request.width === undefined ? {} : { width: request.width }),
            ...(request.height === undefined ? {} : { height: request.height }),
            ...(request.seasonLength === undefined ? {} : { seasonLength: request.seasonLength }),
            ...(request.tickIntervalMinutes === undefined
              ? {}
              : { tickIntervalMinutes: request.tickIntervalMinutes }),
            ...(request.seed === undefined ? {} : { seed: request.seed }),
          },
          { requestId: request.correlationId, headers: await mutationHeaders(request) },
        )
      } catch (err) {
        throw wrap('nda', err)
      }
    },
    async startWorld(request) {
      try {
        return await client.post<{ world: WorldSummary; replayed: boolean }>(
          `/v1/worlds/${encodeURIComponent(request.worldId)}/start`,
          {},
          { requestId: request.correlationId, headers: await mutationHeaders(request) },
        )
      } catch (err) {
        throw wrap('nda', err)
      }
    },
    async setBots(request) {
      try {
        return await client.put<{ bots: number; replayed: boolean }>(
          `/v1/worlds/${encodeURIComponent(request.worldId)}/bots`,
          { enabled: request.enabled, count: request.count },
          { requestId: request.correlationId, headers: await mutationHeaders(request) },
        )
      } catch (err) {
        throw wrap('nda', err)
      }
    },
    async tickWorld(request) {
      try {
        return await client.post<{ queued: boolean; replayed: boolean }>(
          `/v1/worlds/${encodeURIComponent(request.worldId)}/tick`,
          {},
          { requestId: request.correlationId, headers: await mutationHeaders(request) },
        )
      } catch (err) {
        throw wrap('nda', err)
      }
    },
  }
}

/* ------------------------------------------------------------------------ identity */

export interface SetRolesRequest {
  readonly userId: string
  /** The COMPLETE role set the user is to end up with, not a delta. See `setRoles` below. */
  readonly roles: readonly string[]
  /** The operator who approved, as a principal — `user:<uuid>`. Never a service, never the requester. */
  readonly actor: string
  readonly reason: string
  /** The approval this grant is attributed to. Identity's CHECK refuses a grant without one. */
  readonly approvalId: string
  readonly correlationId: string
}

export interface RoleChange {
  readonly roles: readonly string[]
  readonly granted: readonly string[]
  readonly revoked: readonly string[]
}

export interface IdentityClient {
  /** `PUT /internal/users/:id/roles` — identity/src/server.ts, scope `identity:admin`. */
  setRoles(request: SetRolesRequest): Promise<RoleChange>
}

/**
 * The client for the most consequential call this service makes.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS IS THE SERVICE TOKEN, NOT THE OPERATOR'S BEARER, AND THAT IS FORCED BY THE GATE.**
 *
 * Every other executor here forwards the operator's own token where the upstream accepts one, so
 * that the upstream's audit names the human. This one cannot: identity gates the route with
 * `authenticateIdentityAdmin`, which requires a SERVICE token holding `identity:admin`
 * (`identity/src/server.ts`) and refuses an operator token outright. That is deliberate on
 * identity's side and was specified that way by this repository's own `actions.ts` header — a gate
 * built on `authenticateAdmin` would refuse a service token and make the route unreachable from
 * here, which is the exact shape of the defect that left the audit mirror empty all night.
 *
 * **So the human is carried in the BODY, and identity records it rather than inferring it.**
 * `actor` is the approving operator's principal and `approvalId` names the approval. Identity
 * writes a `platform_role_grants` row with `source = 'approval'` in the same transaction as the
 * `users.roles` update, and its deferred constraint trigger refuses the update if that row is
 * missing. So this call cannot promote somebody without leaving the trail, even if a future
 * version of this client forgets to ask for one — the database refuses, not the caller.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function httpIdentityClient(config: ClientConfig): IdentityClient {
  const client = clientFor('identity', config)
  return {
    async setRoles(request) {
      try {
        // Body fields read from identity/src/server.ts: roles, actor, reason,
        // approvalId. All four are required there and `approvalId` must be a uuid.
        return await client.put<RoleChange>(
          `/internal/users/${encodeURIComponent(request.userId)}/roles`,
          {
            roles: [...request.roles],
            actor: request.actor,
            reason: request.reason,
            approvalId: request.approvalId,
          },
          {
            requestId: request.correlationId,
            headers: await authHeader(config, { kind: 'service' }),
          },
        )
      } catch (err) {
        throw wrap('identity', err)
      }
    },
  }
}

/* ------------------------------------------------------------------------ notify */

export interface MailDelivery {
  readonly id: string
  readonly userId: string
  readonly channel: string
  readonly state: string
  readonly outcome: string
  readonly reason: string | null
  readonly attempts: number
  readonly maxAttempts: number
  readonly lastError: string | null
  readonly category: string
  readonly templateId: string
  readonly createdAt: string
  readonly sentAt: string | null
}

export interface NotifyClient {
  /** `GET /admin/deliveries` — notify/src/server.ts. Admin principal, not a service one. */
  mailFor(request: {
    readonly userId?: string
    readonly address?: string
    readonly limit?: number
    readonly bearer: string
    readonly correlationId?: string
  }): Promise<{ deliveries: readonly MailDelivery[]; nextCursor: string | null }>
  /** `POST /admin/deliveries/:id/resend`. 202 with the NEW delivery's id. */
  resend(request: {
    readonly deliveryId: string
    readonly bearer: string
    readonly correlationId?: string
  }): Promise<{ deliveryId: string }>
}

/**
 * Notify's operator surface.
 *
 * **The OPERATOR's bearer is forwarded, not a service token**, and that is the whole design
 * decision here. Both routes are `requireAdmin` in notify — a service principal is refused
 * outright — so a service token would not work without widening that gate. More importantly it
 * should not: resending somebody's mail is an act by a named human, and forwarding the token they
 * already presented keeps the authorisation decision in notify, against the real person, instead
 * of turning every action into "admin-api did it".
 *
 * It also means no new credential to mint, store or rotate, which is the cheapest kind of secret
 * to get right.
 */
export function httpNotifyClient(config: ClientConfig): NotifyClient {
  const client = clientFor('notify', config)
  return {
    async mailFor(request) {
      try {
        const query = new URLSearchParams()
        if (request.userId !== undefined) query.set('user', request.userId)
        if (request.address !== undefined) query.set('address', request.address)
        query.set('limit', String(request.limit ?? 50))
        return await client.get<{ deliveries: readonly MailDelivery[]; nextCursor: string | null }>(
          `/admin/deliveries?${query.toString()}`,
          {
            ...(request.correlationId ? { requestId: request.correlationId } : {}),
            headers: await authHeader(config, { kind: 'operator', bearer: request.bearer }),
          },
        )
      } catch (err) {
        throw wrap('notify', err)
      }
    },
    async resend(request) {
      try {
        // 202, and the body names the NEW delivery. Notify queues a second delivery beside the
        // original rather than resetting it, so the failure being repeated stays readable.
        return await client.post<{ deliveryId: string }>(
          `/admin/deliveries/${encodeURIComponent(request.deliveryId)}/resend`,
          {},
          {
            ...(request.correlationId ? { requestId: request.correlationId } : {}),
            headers: await authHeader(config, { kind: 'operator', bearer: request.bearer }),
          },
        )
      } catch (err) {
        throw wrap('notify', err)
      }
    },
  }
}

/* ------------------------------------------------------------------------ the wiring */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THE WIRING LIVES HERE AND NOT IN `index.ts`.**
 *
 * Because the defect was a WIRING defect, and wiring that lives in the composition root is wiring
 * no test can reach. `index.ts` opens a pool, asserts a schema, claims an estate identity, starts a
 * job runner and calls `listen()` — importing it from a test starts a server against a database. So
 * the line that was wrong,
 *
 *     const serviceToken = () => env.serviceToken        // index.ts, for the life of the
 *                                                        // process and of the container
 *
 * was structurally untestable, and this repository's 311-line `upstreams.test.ts` could not have
 * caught it however carefully it had been written: every case in it builds its own `config()` with
 * its own token, so it proves the CLIENTS work and says nothing about what the SERVICE hands them.
 * `wallet/src/upstreams.ts`, `market/src/upstreams.ts` and `foresight/src/upstreams.ts` each
 * learned this the same way. `servicetoken.test.ts` beside this file goes through the function
 * below, and reverting its body to `() => env.serviceToken` turns that file red.
 *
 * **ONE PROVIDER FOR ALL FOUR PEERS**, for the same reason there was one token: it is minted for
 * `service:admin-api` carrying the scopes admin-api needs — `ledger:post`, `ledger:read`,
 * `identity:admin` — and each peer checks the one it cares about. Four providers would be four
 * exchanges and four refresh schedules against one identity for one process.
 *
 * **BOTH HOOKS, AND THE SECOND IS NOT DECORATION.** `serviceToken` keeps the bearer fresh on a
 * schedule computed from this process's clock. `fetch` is the provider's `authorizedFetch`, which
 * catches a 401 from a peer, discards exactly the token that was refused, re-mints and replays
 * once. Without the second, correctness would rest on this process and the ledger agreeing about
 * what time it is — and on no credential ever being revoked mid-flight.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * How this process obtains a service bearer, NAMED rather than inferred from whether a string is
 * set.
 *
 * `exchanged` is correct. `static` is the defect, still running wherever a deployment has not yet
 * been given the credential its bootstrap already mints. `none` cannot authenticate at all. Three
 * states, because "the bearer stopped working" and "there is no bearer" send an operator to
 * different places at three in the morning — and this service is where they come to look.
 */
export type CredentialMode = 'exchanged' | 'static' | 'none'

export interface Upstreams {
  readonly mode: CredentialMode
  /** `null` unless `mode` is `exchanged`. What `index.ts` samples for the readiness gauge. */
  readonly identityTokens: ServiceTokenProvider | null
  readonly ledger: LedgerClient
  readonly market: MarketClient
  readonly billing: BillingClient
  readonly identity: IdentityClient
  readonly notify: NotifyClient
  /** Forge Worlds' game service. Reachable only from inside the estate — see `httpNdaClient`. */
  readonly nda: NdaClient
  /** The shared config, so `probeReadiness` can be called for a peer with the same transport. */
  readonly clientConfig: Omit<ClientConfig, 'baseUrl'>
  /**
   * The same six peers, narrowed to ONE estate: every call they make carries that estate's
   * `CF-Network`, so a consolidated peer answers from the right side.
   *
   * `forRequest` in `server.ts` swaps them in per request. The six fields above stay as the
   * boot-time set — they send no `CF-Network` at all, which is what a peer that has not been
   * consolidated yet still expects.
   */
  for(network: Network): Pick<Upstreams, 'ledger' | 'market' | 'billing' | 'identity' | 'notify' | 'nda'>
}

/** The subset of `Env` this needs. Named so a test does not have to build a whole environment. */
export type UpstreamEnv = Pick<
  Env,
  | 'identityUrl'
  | 'identityCredential'
  | 'serviceToken'
  | 'ledgerUrl'
  | 'notifyUrl'
  | 'marketUrl'
  | 'billingUrl'
  | 'ndaUrl'
  | 'upstreamDeadlineMs'
>

export interface UpstreamOptions {
  /** Test seam. Production uses the global `fetch`. */
  readonly fetch?: typeof globalThis.fetch | undefined
  readonly onEvent?: ((event: ProviderEvent) => void) | undefined
  readonly onResult?: ((event: ResultEvent) => void) | undefined
}

export function buildUpstreams(env: UpstreamEnv, options: UpstreamOptions = {}): Upstreams {
  const identityTokens = env.identityCredential
    ? new ServiceTokenProvider({
        identityUrl: env.identityUrl,
        credential: env.identityCredential,
        // Not narrowed. Identity issues this service's whole allowlist, and at boot this process
        // cannot know which of its call sites will be reached first — a ledger reversal approved
        // at 02:00, a trial-balance tile rendered on the first page load, or a role grant. A
        // narrowing that drifted from `deploy/scripts/derive-grants.mjs` would 403 with nothing in
        // either log naming the cause.
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.onEvent ? { onEvent: options.onEvent } : {}),
      })
    : null

  // **THE CREDENTIAL WINS.** This is the state the estate will actually be in for one deploy:
  // `ADMIN_API_SERVICE_TOKEN` is set today and stays set while the credential is added. If the
  // pre-minted token won, the deploy would look correct, the boot log would say `exchanged`, and
  // the cliff would still be there.
  const mode: CredentialMode = identityTokens ? 'exchanged' : env.serviceToken ? 'static' : 'none'

  /**
   * What every `{ kind: 'service' }` call site asks for its bearer.
   *
   * **Rejects rather than resolving `undefined` or `''` when there is nothing to present.** An
   * empty bearer goes out as the literal `Bearer `, comes back 401, and tells an operator that the
   * LEDGER refused admin-api — when the truth is that nobody configured admin-api. Those are
   * different mornings and this service exists to keep them apart.
   * `ServiceTokenUnavailableError` maps to 503 under `statusFor`, never 401, for the same reason
   * `Verifier` answers 503 on an unreachable JWKS: a fault in the thing that decides authentication
   * is not evidence that the caller is unauthenticated.
   */
  const serviceToken = (): Promise<string> => {
    if (identityTokens) return identityTokens.token()
    if (env.serviceToken) return Promise.resolve(env.serviceToken)
    return Promise.reject(
      new ServiceTokenUnavailableError(
        'no identity credential is configured; set ADMIN_API_IDENTITY_CREDENTIAL ' +
          '(long-lived, cfsc_…, from POST /service-credentials)',
      ),
    )
  }

  // The provider's own `fetch` is the transport it EXCHANGES over; `authorizedFetch` is what the
  // four clients get. It is the layer where a 401 is visible and where the header was set, so
  // hooking it needs no change at any call site above and cannot be forgotten at one of them.
  const fetch = identityTokens?.authorizedFetch ?? options.fetch
  const clientConfig = {
    deadlineMs: env.upstreamDeadlineMs,
    serviceToken,
    ...(fetch ? { fetch } : {}),
    ...(options.onResult ? { onResult: options.onResult } : {}),
  }

  /**
   * The six peers, as seen from ONE estate.
   *
   * Built per network at boot rather than per request: there is no circuit state on these clients
   * to split between two sets, and a set built per request would allocate six `HttpClient`s to
   * serve one call.
   */
  const peersFor = (network?: Network) => {
    const config = { ...clientConfig, ...(network ? { network } : {}) }
    return {
      ledger: httpLedgerClient({ baseUrl: env.ledgerUrl, ...config }),
      notify: httpNotifyClient({ baseUrl: env.notifyUrl, ...config }),
      market: httpMarketClient({ baseUrl: env.marketUrl, ...config }),
      billing: httpBillingClient({ baseUrl: env.billingUrl, ...config }),
      nda: httpNdaClient({ baseUrl: env.ndaUrl, ...config }),
      // The role-grant upstream. Presents this service's own bearer, never an operator's —
      // identity's `identity:admin` gate refuses a user principal outright (identity/src/server.ts).
      identity: httpIdentityClient({ baseUrl: env.identityUrl, ...config }),
    }
  }

  const byNetwork: Record<Network, ReturnType<typeof peersFor>> = {
    mainnet: peersFor('mainnet'),
    testnet: peersFor('testnet'),
  }

  return {
    mode,
    identityTokens,
    clientConfig,
    /** The peers for one estate. Every call they make carries that estate's `CF-Network`. */
    for: (network: Network) => byNetwork[network],
    // The boot-time set, for the composition root and for anything that runs off the request path.
    // No `CF-Network` at all, which is what a single-network peer still expects.
    ...peersFor(),
  }
}
