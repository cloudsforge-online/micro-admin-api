/**
 * The database harness and the local fakes.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A DATABASE TEST RUNS ONLY AGAINST A DATABASE WHOSE NAME SAYS IT IS A TEST DATABASE.**
 *
 * Not a convenience: `resetAdminApi` truncates every table this service owns, and requiring "test"
 * in the name is the difference between a red build and an emptied environment. This service holds
 * the **estate's audit of record** — the hash-chained mirror that SD-15 says is the only thing
 * that can answer "who did what, to whose data, and was it allowed" months later under dispute.
 * The wrong connection string here does not lose test data; it destroys the evidence every future
 * investigation in the estate would run on, and it does so in a way the chain itself cannot
 * detect, because a TRUNCATE leaves no gap.
 *
 * Only an `admin_api_test` database is ever created or written by this suite. The rule and its
 * wording are taken from `beacon/src/testsupport.ts` and `market/src/testsupport.ts`, because a
 * harness that differs per service is a harness somebody gets wrong once.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Not a test file itself: it is excluded from the build and contains no `test()` call.
 */

import { createServer as createHttpServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import postgres from 'postgres'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { Logger, Metrics } from '@cloudsforge/telemetry'
import { Lifecycle } from '@cloudsforge/lifecycle'
import type { Principal } from '@cloudsforge/auth'
import { MIGRATIONS, SEQUENCES, TABLES } from './migrations.ts'
import { registerServiceMetrics } from './server.ts'
import type { Db } from './outbox.ts'
import type {
  AccountBalance,
  BillingClient,
  IdentityClient,
  EntryPosting,
  LedgerClient,
  MarketClient,
  ModerationCase,
  PostedEntry,
  ReversedEntry,
  RevokeResult,
  TrialBalance,
} from './upstreams.ts'
import { UpstreamError } from './upstreams.ts'
import type { EstateDeps } from './estate.ts'

const url = process.env['ADMIN_API_TEST_DATABASE_URL']

export const enabled = Boolean(url && /test/i.test(url))

export const skip = enabled ? false : 'set ADMIN_API_TEST_DATABASE_URL (name must contain "test")'

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/** Bring the schema up. Idempotent, so every test file may call it and only the first does work. */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'admin-api-test' })
}

/**
 * Empty every table this service owns, and restart the audit sequence.
 *
 * The sequence restart is not cosmetic. `audit_events.seq` is HASHED, so a chain built after a
 * truncate that did not reset the sequence would start at seq 400 with `prev_hash = GENESIS` —
 * which is a legal chain, but not the one the tests assert about, and the difference would show up
 * as a confusing mismatch in exactly one test file rather than as an obvious harness bug.
 */
export async function resetAdminApi(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${[...TABLES, 'jobs'].join(', ')} restart identity cascade`)
  for (const sequence of SEQUENCES) await sql.unsafe(`alter sequence ${sequence} restart with 1`)
  // ── RE-SEEDED AFTER EVERY RESET, because a backup or a restore is REFUSED by an estate that has
  //    not claimed an identity — that refusal is the control, not an inconvenience. TRUNCATE fires
  //    no row triggers, so `estate_identity_immutable` does not block the reset the way a DELETE
  //    would; the row is simply re-established here so each test starts in a bootable estate.
  //
  //    `TEST_ENVIRONMENT` is `testnet` ON PURPOSE. Every fixture backup is therefore a testnet
  //    backup, so a test that accidentally exercised a cross-environment restore against a
  //    `mainnet` fixture gets the refusal rather than a pass.
  await sql.unsafe(
    `insert into estate_identity (singleton, environment, claimed_by)
     values (true, $1, 'service:admin-api@test') on conflict (singleton) do nothing`,
    [TEST_ENVIRONMENT],
  )
  await sql.unsafe(
    `insert into backup_settings (singleton, updated_by) values (true, 'test')
     on conflict (singleton) do nothing`,
  )
}

/** The environment every test estate claims. See `resetAdminApi` for why it is not `mainnet`. */
export const TEST_ENVIRONMENT = 'testnet'

/** Logs are discarded rather than silenced, so a serialisation failure still throws. */
export function quietLogger(): Logger {
  return new Logger({ service: 'admin-api-test', sink: () => {} })
}

export function testMetrics(): Metrics {
  return registerServiceMetrics(new Metrics())
}

export const db = (sql: postgres.Sql): Db => sql as unknown as Db

/* ------------------------------------------------------------------ principals */

export const ALICE = '11111111-1111-4111-8111-111111111111'
export const BOB = '22222222-2222-4222-8222-222222222222'
export const CAROL = '33333333-3333-4333-8333-333333333333'

/** The two operators every four-eyes test needs. Named, so a test reads as a sentence. */
export const OPERATOR_ONE = `user:${ALICE}`
export const OPERATOR_TWO = `user:${BOB}`

export function operatorPrincipal(userId: string): Principal {
  return { kind: 'user', userId, handle: `op-${userId.slice(0, 4)}`, roles: ['admin'] }
}

export function playerPrincipal(userId: string): Principal {
  return { kind: 'user', userId, handle: `player-${userId.slice(0, 4)}`, roles: ['player'] }
}

export function servicePrincipal(service: string, scopes: readonly string[]): Principal {
  return { kind: 'service', service, scopes: [...scopes] }
}

/**
 * A verifier keyed by opaque bearer string.
 *
 * The token IS the lookup key, which is what lets a route test forward "the operator's own bearer"
 * to a fake upstream and assert that the RIGHT operator's token arrived — the property SD-11 calls
 * the one genuinely good decision in nimbus's admin proxies.
 */
export interface FakeVerifier {
  principal(token: string): Promise<Principal>
  add(token: string, principal: Principal): void
  /** Make every verification fail the way an unreachable JWKS does: 503, never 401. */
  unavailable(value: boolean): void
}

export function fakeVerifier(entries: Record<string, Principal> = {}): FakeVerifier {
  const byToken = new Map(Object.entries(entries))
  let down = false
  return {
    add(token, principal) {
      byToken.set(token, principal)
    },
    unavailable(value) {
      down = value
    },
    async principal(token) {
      if (down) {
        const { VerifierUnavailableError } = await import('@cloudsforge/auth')
        throw new VerifierUnavailableError('the JWKS could not be fetched')
      }
      const found = byToken.get(token)
      if (!found) {
        const { TokenError } = await import('@cloudsforge/auth')
        throw new TokenError('unknown token', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED')
      }
      return found
    },
  }
}

/* ------------------------------------------------------------------ fake upstreams */

export interface FakeLedger extends LedgerClient {
  readonly reversals: Array<{ entryId: string; idempotencyKey: string; operator: string; approvalId: string }>
  /** Entries posted through `postEntry`, in order, with the postings the caller built. */
  readonly entries: Array<{ kind: string; idempotencyKey: string; approvalId: string; postings: readonly EntryPosting[] }>
  /** Replays on a repeated key, exactly as the real ledger does. */
  readonly postedCount: number
  failWith(err: Error | null): void
  setTrialBalance(value: TrialBalance): void
  /** Stub the balances one subject reports. */
  setBalances(subject: string, balances: readonly AccountBalance[]): void
  /**
   * Forget everything.
   *
   * A recorded call list that survived between test cases would make `reversals.length === 1`
   * true only when the file happened to run that case first — which is how a suite ends up
   * passing alone and failing together, and it did here before this existed.
   */
  reset(): void
}

/**
 * **The fake ledger REPLAYS ON A REPEATED KEY**, exactly as the real one does.
 *
 * Not decoration: `EXECUTORS['ledger.entry.reverse']` derives its idempotency key from the
 * approval id precisely so a retried execution cannot post a second reversal, and a fake that
 * posted twice would let that bug pass every test here and fail against the real thing.
 */
export function fakeLedger(): FakeLedger {
  const reversals: FakeLedger['reversals'] = []
  const entries: FakeLedger['entries'] = []
  const byKey = new Map<string, ReversedEntry>()
  const postedByKey = new Map<string, PostedEntry>()
  const balancesBySubject = new Map<string, readonly AccountBalance[]>()
  let failure: Error | null = null
  let trial: TrialBalance = { balanced: true, totalAbsoluteDelta: '0' }

  return {
    reversals,
    entries,
    get postedCount() {
      return byKey.size + postedByKey.size
    },
    failWith(err) {
      failure = err
    },
    setTrialBalance(value) {
      trial = value
    },
    setBalances(subject, balances) {
      balancesBySubject.set(subject, balances)
    },
    reset() {
      reversals.length = 0
      entries.length = 0
      byKey.clear()
      postedByKey.clear()
      balancesBySubject.clear()
      failure = null
      trial = { balanced: true, totalAbsoluteDelta: '0' }
    },
    async reverseEntry(request) {
      reversals.push({
        entryId: request.entryId,
        idempotencyKey: request.idempotencyKey,
        operator: request.operator,
        approvalId: request.approvalId,
      })
      if (failure) throw failure
      const replay = byKey.get(request.idempotencyKey)
      if (replay) return { ...replay, replayed: true }
      const entry: ReversedEntry = {
        id: `entry-${byKey.size + 1}`,
        reversesEntryId: request.entryId,
        replayed: false,
      }
      byKey.set(request.idempotencyKey, entry)
      return entry
    },
    async postEntry(request) {
      entries.push({
        kind: request.kind,
        idempotencyKey: request.idempotencyKey,
        approvalId: request.approvalId,
        postings: request.postings,
      })
      if (failure) throw failure
      // Replays on a repeated key, exactly as the real ledger does — the engagement transfer
      // executor derives its key from the approval id so a retry moves nothing twice, and a fake
      // that posted twice would let that bug pass here and fail against the real thing.
      const replay = postedByKey.get(request.idempotencyKey)
      if (replay) return { ...replay, replayed: true }
      const entry: PostedEntry = { id: `posted-${postedByKey.size + 1}`, replayed: false }
      postedByKey.set(request.idempotencyKey, entry)
      return entry
    },
    async trialBalance() {
      if (failure) throw failure
      return trial
    },
    async balancesForSubject(subject) {
      if (failure) throw failure
      return balancesBySubject.get(subject) ?? []
    },
  }
}

export interface FakeMarket extends MarketClient {
  readonly resolved: Array<{ caseId: string; state: string; bearer: string }>
  readonly reads: string[]
  setOpenCases(cases: readonly ModerationCase[]): void
  failWith(err: Error | null): void
  reset(): void
}

export function fakeMarket(): FakeMarket {
  const resolved: FakeMarket['resolved'] = []
  const reads: string[] = []
  let open: readonly ModerationCase[] = []
  let failure: Error | null = null

  return {
    resolved,
    reads,
    setOpenCases(cases) {
      open = cases
    },
    failWith(err) {
      failure = err
    },
    reset() {
      resolved.length = 0
      reads.length = 0
      open = []
      failure = null
    },
    async resolveCase(request) {
      if (failure) throw failure
      resolved.push({ caseId: request.caseId, state: request.state, bearer: request.operatorBearer })
      return { id: request.caseId, state: request.state === 'upheld' ? 'upheld' : 'dismissed' }
    },
    async openCases(bearer) {
      reads.push(bearer)
      if (failure) throw failure
      return open
    },
  }
}

/**
 * The role-grant upstream.
 *
 * `grants` records the EXACT body sent, because the two things most easily got wrong on this call
 * are silent and both are caught by inspecting it: sending `[role]` (which revokes `player`) and
 * omitting `approvalId` (which identity's CHECK refuses, creating an unattributed administrator
 * only if that CHECK were ever relaxed). `actions.test.ts` asserts on both.
 */
export interface FakeIdentity extends IdentityClient {
  readonly grants: Array<{
    userId: string
    roles: readonly string[]
    actor: string
    reason: string
    approvalId: string
  }>
  failWith(err: Error | null): void
  reset(): void
}

export function fakeIdentity(): FakeIdentity {
  const grants: FakeIdentity['grants'] = []
  let failure: Error | null = null
  return {
    grants,
    failWith(err) {
      failure = err
    },
    reset() {
      grants.length = 0
      failure = null
    },
    async setRoles(request) {
      if (failure) throw failure
      grants.push({
        userId: request.userId,
        roles: [...request.roles],
        actor: request.actor,
        reason: request.reason,
        approvalId: request.approvalId,
      })
      // Identity diffs against what the user holds; every registered user holds `player`.
      const previous = ['player']
      return {
        roles: [...request.roles],
        granted: request.roles.filter((r) => !previous.includes(r)),
        revoked: previous.filter((r) => !request.roles.includes(r)),
      }
    },
  }
}

export interface FakeBilling extends BillingClient {
  readonly revocations: Array<{ entitlementId: string; reason: string; refund: boolean; bearer: string }>
  failWith(err: Error | null): void
  setResult(value: RevokeResult): void
  reset(): void
}

export function fakeBilling(): FakeBilling {
  const revocations: FakeBilling['revocations'] = []
  let failure: Error | null = null
  let result: RevokeResult = { alreadyRevoked: false, reversalEntryId: 'entry-refund-1' }

  return {
    revocations,
    failWith(err) {
      failure = err
    },
    setResult(value) {
      result = value
    },
    reset() {
      revocations.length = 0
      failure = null
      result = { alreadyRevoked: false, reversalEntryId: 'entry-refund-1' }
    },
    async revokeEntitlement(request) {
      if (failure) throw failure
      revocations.push({
        entitlementId: request.entitlementId,
        reason: request.reason,
        refund: request.refund,
        bearer: request.operatorBearer,
      })
      return result
    },
  }
}

/** An unreachable upstream, which is a genuinely different failure from a refusal. */
export function unreachable(name: string): UpstreamError {
  return new UpstreamError(name, `${name} could not be reached`, null, false)
}

/** An upstream that answered. 4xx means it decided; retrying produces the same answer. */
export function refused(name: string, status: number): UpstreamError {
  return new UpstreamError(name, `${name} answered ${status}`, status, status >= 400 && status < 500)
}

/** Readiness probes for the estate view, controllable per service. */
export function fakeReadiness(
  states: Record<string, { ready: boolean; state: string; detail?: string } | 'throw'>,
): EstateDeps['readiness'] {
  return Object.entries(states).map(([name, value]) => ({
    name,
    probe: async () => {
      if (value === 'throw') throw unreachable(name)
      return { ready: value.ready, state: value.state, detail: value.detail ?? null }
    },
  }))
}

/* ------------------------------------------------------------------ a real HTTP target */

export interface FakeTarget {
  readonly baseUrl: string
  readonly hits: readonly { path: string; body: string; headers: Record<string, string> }[]
  setStatus(status: number): void
  setBody(body: unknown): void
  /**
   * Stop answering entirely.
   *
   * The socket is accepted and then nothing is written — which is what a wedged upstream actually
   * looks like, and is a genuinely different failure from a refused connection. A test that only
   * ever simulates ECONNREFUSED never exercises the deadline.
   */
  hang(value: boolean): void
  close(): Promise<void>
}

export async function fakeTarget(): Promise<FakeTarget> {
  const hits: Array<{ path: string; body: string; headers: Record<string, string> }> = []
  let status = 200
  let payloadValue: unknown = { ok: true }
  let hanging = false
  const open = new Set<import('node:net').Socket>()

  const server: Server = createHttpServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(req.headers)) {
        headers[key] = Array.isArray(value) ? (value[0] ?? '') : (value ?? '')
      }
      hits.push({ path: req.url ?? '/', body: Buffer.concat(chunks).toString('utf8'), headers })
      if (hanging) return
      const payload = `${JSON.stringify(payloadValue)}\n`
      res.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(payload),
      })
      res.end(payload)
    })
  })
  server.on('connection', (socket) => {
    open.add(socket)
    socket.on('close', () => open.delete(socket))
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    hits,
    setStatus(value) {
      status = value
    },
    setBody(value) {
      payloadValue = value
    },
    hang(value) {
      hanging = value
    },
    close: () =>
      new Promise<void>((resolve) => {
        // A hung request holds its socket open, so `server.close()` alone would never call back
        // and the test file would sit there until the runner killed it.
        for (const socket of open) socket.destroy()
        server.close(() => resolve())
      }),
  }
}

/* ------------------------------------------------------------------ a running server */

export interface Harness {
  readonly baseUrl: string
  readonly metrics: Metrics
  readonly ledger: FakeLedger
  readonly market: FakeMarket
  readonly billing: FakeBilling
  readonly identity: FakeIdentity
  readonly verifier: FakeVerifier
  request(
    method: string,
    path: string,
    options?: { token?: string; body?: unknown; headers?: Record<string, string> },
  ): Promise<{ status: number; body: any; text: string; headers: Record<string, string> }>
  /** Forget every fake upstream's recorded calls. Call from `beforeEach`, beside the truncate. */
  reset(): void
  close(): Promise<void>
}

export interface HarnessOptions {
  /**
   * The secrets the inbound event route will ACCEPT, newest first — a list, not a value, so a test
   * can stage the overlap window a rolling rotation of `OUTBOX_SIGNING_SECRET` depends on.
   */
  readonly acceptSecrets?: readonly string[]
  readonly approvalTtlMinutes?: number
  readonly readiness?: EstateDeps['readiness']
  readonly now?: () => Date
}

/** Boot the real server over a real socket, with fake upstreams and a real database. */
export async function startHarness(
  sql: postgres.Sql,
  verifier: FakeVerifier,
  options: HarnessOptions = {},
): Promise<Harness> {
  const { createServer } = await import('./server.ts')
  const metrics = testMetrics()
  const { registerHttpMetrics } = await import('@cloudsforge/telemetry')
  registerHttpMetrics(metrics)
  const ledger = fakeLedger()
  const market = fakeMarket()
  const billing = fakeBilling()
  const identity = fakeIdentity()
  const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 100 })
  lifecycle.markReady()

  const server = createServer({
    lifecycle,
    logger: quietLogger(),
    metrics,
    verifier,
    sql: db(sql),
    producer: 'admin-api',
    ledger,
    market,
    billing,
    identity,
    readiness: options.readiness ?? fakeReadiness({ ledger: { ready: true, state: 'ready' } }),
    estateEnvironment: TEST_ENVIRONMENT,
    composeProject: 'cf-testnet',
    eventAcceptSecrets: options.acceptSecrets ?? ['a-test-signing-secret-of-sufficient-length'],
    approvalTtlMinutes: options.approvalTtlMinutes ?? 240,
    ...(options.now ? { now: options.now } : {}),
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  const baseUrl = `http://127.0.0.1:${port}`

  return {
    baseUrl,
    metrics,
    ledger,
    market,
    billing,
    identity,
    verifier,
    async request(method, path, opts = {}) {
      const headers: Record<string, string> = { ...opts.headers }
      if (opts.token) headers['authorization'] = `Bearer ${opts.token}`
      let sent: string | undefined
      if (opts.body !== undefined) {
        sent = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)
        headers['content-type'] = 'application/json'
      }
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        ...(sent !== undefined ? { body: sent } : {}),
      })
      const text = await response.text()
      const out: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        out[key] = value
      })
      // `/metrics` answers Prometheus text, not JSON. Parsing unconditionally made that route's
      // test fail on a SyntaxError rather than on anything about the route.
      let body: unknown = null
      if (text.length > 0) {
        try {
          body = JSON.parse(text)
        } catch {
          body = null
        }
      }
      return { status: response.status, body, text, headers: out }
    },
    reset() {
      ledger.reset()
      market.reset()
      billing.reset()
      identity.reset()
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

/** A distinct idempotency key per call, so a test never accidentally replays. */
let keyCounter = 0
export function freshKey(prefix = 'test'): string {
  keyCounter += 1
  return `${prefix}-idempotency-key-${keyCounter}`
}
