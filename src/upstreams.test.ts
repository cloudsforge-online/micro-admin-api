/**
 * The upstream clients — against a real HTTP socket, not a stubbed `fetch`.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE REQUEST THIS SERVICE SENDS IS ASSERTED, FIELD BY FIELD.**
 *
 * 18-build-status.md records six occasions in this estate where a client was built against an
 * imagined surface, one of which returned 403 on every marketplace listing, and one of which is
 * still live: `wallet/src/pricingclient.ts` calls `GET /v1/quotes`, which pricing does not serve —
 * pricing's rate board is `GET /rates`. The route citations in `upstreams.ts` are how the next one
 * gets caught, and these tests are what make the citations checkable: the exact path, the exact
 * body field names, and the exact bearer.
 *
 * Field names below were read from the providers' handlers:
 *   ledger   server.ts — originatingService, actor, correlationId, idempotencyKey,
 *                                description, kind, metadata
 *   market   server.ts — state ('upheld'|'dismissed'), notes. `resolvedBy` is NOT a body
 *                                field: market derives it from the principal, which is why the
 *                                operator's bearer is forwarded rather than this service's.
 *   billing  server.ts — reason (required, non-empty), refund (boolean)
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  BILLING_SCOPES,
  IDENTITY_SCOPES,
  LEDGER_SCOPES,
  MARKET_SCOPES,
  UpstreamError,
  httpBillingClient,
  httpLedgerClient,
  httpMarketClient,
  probeReadiness,
  type ClientConfig,
} from './upstreams.ts'
import { ENTRY_KINDS, isEntryKind } from '@cloudsforge/contracts-money'
import { ENGAGEMENT_TRANSFER_KIND } from './engagement.ts'
import { fakeTarget, type FakeTarget } from './testsupport.ts'

let target: FakeTarget

beforeEach(async () => {
  target = await fakeTarget()
})
afterEach(async () => {
  await target.close()
})

const SERVICE_TOKEN = 'this-services-own-scoped-service-token'
const OPERATOR_BEARER = 'the-operators-own-bearer'

function config(overrides: Partial<ClientConfig> = {}): ClientConfig {
  return {
    baseUrl: target.baseUrl,
    deadlineMs: 2_000,
    // `async`, because the seam is now `() => Promise<string>`: the bearer is MINTED at the moment
    // the header is built rather than read once at boot. Every case in this file still supplies a
    // fixed string, and that is the limit of what this file can say — see `servicetoken.test.ts`,
    // which drives `buildUpstreams` past a token's own expiry because a suite of cases that each
    // build their own client is exactly what could not see micro-org #222.
    serviceToken: async () => SERVICE_TOKEN,
    ...overrides,
  }
}

/* --------------------------------------------- the declared grant, and the call sites it covers */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THESE FOUR CASES ARE THE TEETH ON `*_SCOPES` — micro-org #317.**
 *
 * `upstreams.ts` now exports `LEDGER_SCOPES`, `IDENTITY_SCOPES`, `MARKET_SCOPES` and
 * `BILLING_SCOPES` for `deploy/scripts/derive-grants.mjs` to read. Nothing in this repository
 * imports them at runtime, and a constant no code reads is exactly the kind of thing that drifts
 * away from the calls it describes without a single test going red — which is how the boxed claim
 * in `actions.ts` came to assert for months that this service's token lacked `identity:admin`.
 * Replacing a stale hand-written note in one repository with a stale hand-written constant in
 * another would be no improvement at all.
 *
 * So the declaration is checked against the CALL SITES rather than against the estate. The
 * discriminator is the one `derive-grants.mjs` itself uses: a method that reaches an upstream with
 * `{ kind: 'service' }` is presenting THIS service's token and its scope must be declared; a method
 * that reaches one with `{ kind: 'operator', bearer }` is presenting the human's and no scope of
 * ours makes it stronger. The first two cases assert that both service-token clients send our
 * bearer; the third asserts, from the source, that the clients declaring nothing have no
 * `{ kind: 'service' }` call site to justify one.
 *
 * The estate half was measured rather than asserted here, because a unit test cannot reach it:
 * with the `admin-api/src/upstreams.ts` entry removed from `grant-gaps.json`,
 * `derive-grants.mjs --json` produced `admin-api -> identity:admin ledger:post ledger:read` on
 * 2026-08-10 — the same three scopes `IDENTITY_SERVICE_TOKEN_GRANTS` already carries in the
 * running estate, so `--check` passes with the compose block BYTE-IDENTICAL. That is the proof
 * standard `grant-gaps.json` sets for its own deletions, and it is what makes the entry stale
 * rather than merely deletable.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

test('EVERY SCOPE THIS SERVICE DECLARES IS ONE A SERVICE-TOKEN CALL SITE NEEDS', () => {
  // Not an alphabetised copy of the compose file: these are the two clients that pass
  // `{ kind: 'service' }`, and each scope below has a method under it in this same suite.
  assert.deepEqual([...LEDGER_SCOPES].sort(), ['ledger:post', 'ledger:read'])
  assert.deepEqual([...IDENTITY_SCOPES], ['identity:admin'])
  // Least privilege runs both ways. An operator-bearer client granted a scope would be a real
  // capability on a real token that no receiving gate ever consults — AD-05's failure shape.
  assert.deepEqual([...MARKET_SCOPES], [])
  assert.deepEqual([...BILLING_SCOPES], [])
})

test('A CLIENT THAT DECLARES NO SCOPE MAY NOT PRESENT THE SERVICE TOKEN', async () => {
  // Source-level, deliberately. A behavioural test can only catch a method somebody remembered to
  // exercise; this catches the NEXT method — one added to the market or billing client with
  // `{ kind: 'service' }` copied from its neighbour, which would silently need a grant nobody has
  // declared and would fail in the estate as a 403 rather than here.
  const { readFileSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const source = readFileSync(fileURLToPath(new URL('./upstreams.ts', import.meta.url)), 'utf8')

  // Each client's body runs from its factory to the next top-level `export`, which is how this
  // file is laid out: one `httpXClient` per upstream, nothing interleaved.
  const bodyOf = (factory: string): string => {
    const from = source.indexOf(`export function ${factory}(`)
    assert.ok(from >= 0, `${factory} is gone — this test is reading a file that no longer exists`)
    const next = source.indexOf('\nexport ', from + 1)
    return source.slice(from, next < 0 ? source.length : next)
  }

  for (const [factory, scopes] of [
    ['httpMarketClient', MARKET_SCOPES],
    ['httpBillingClient', BILLING_SCOPES],
  ] as const) {
    assert.equal(scopes.length, 0, `${factory}'s constant changed — update this case deliberately`)
    assert.equal(
      /kind: 'service'/.test(bodyOf(factory)),
      false,
      `${factory} presents this service's token but declares no scope: either forward the operator's bearer, or declare what identity must mint`,
    )
  }

  // And the converse, so the check cannot pass by reading nothing: the two clients that DO declare
  // are the two that do present it.
  for (const factory of ['httpLedgerClient', 'httpIdentityClient']) {
    assert.ok(/kind: 'service'/.test(bodyOf(factory)), `${factory} no longer presents the service token`)
  }
})

/* ------------------------------------------------------------------ ledger */

test('the ledger reversal hits the cited path with the cited body', async () => {
  target.setBody({ entry: { id: 'entry-9', reversesEntryId: 'entry-1' }, replayed: false })
  const client = httpLedgerClient(config())

  const result = await client.reverseEntry({
    entryId: 'entry-1',
    idempotencyKey: 'admin-api:approval:abc',
    description: 'reversing a duplicated sweep',
    correlationId: 'req-1',
    operator: 'user:11111111-1111-4111-8111-111111111111',
    approvalId: 'abc',
  })

  assert.equal(result.id, 'entry-9')
  const hit = target.hits[0]!
  assert.equal(hit.path, '/entries/entry-1/reverse')
  const body = JSON.parse(hit.body)
  assert.equal(body.originatingService, 'admin-api')
  // `actor` is typed `service:${string}` at ledger/src/server.ts, which is why the human
  // travels in metadata rather than in the field whose name suggests it.
  assert.equal(body.actor, 'service:admin-api')
  assert.equal(body.idempotencyKey, 'admin-api:approval:abc')
  assert.equal(body.correlationId, 'req-1')
  assert.equal(body.metadata.operator, 'user:11111111-1111-4111-8111-111111111111')
  assert.equal(body.metadata.approvalId, 'abc')
  // Named so an auditor reading the ledger alone knows where the human is recorded.
  assert.equal(body.metadata.operatorRecordedIn, 'admin-api audit_events')
})

test('THE LEDGER GETS THIS SERVICE\'S TOKEN, because it refuses a user principal', async () => {
  // ledger/src/server.ts `authorise` throws ForbiddenError on a non-service principal outright.
  // Forwarding the operator's bearer there would be a guaranteed 403.
  target.setBody({ entry: { id: 'e', reversesEntryId: null }, replayed: false })
  await httpLedgerClient(config()).reverseEntry({
    entryId: 'entry-1',
    idempotencyKey: 'k',
    description: 'd',
    correlationId: 'c',
    operator: 'user:x',
    approvalId: 'a',
  })
  assert.equal(target.hits[0]?.headers['authorization'], `Bearer ${SERVICE_TOKEN}`)
})

test('the reversal carries an Idempotency-Key header as well as a body field', async () => {
  target.setBody({ entry: { id: 'e', reversesEntryId: null }, replayed: false })
  await httpLedgerClient(config()).reverseEntry({
    entryId: 'entry-1',
    idempotencyKey: 'admin-api:approval:abc',
    description: 'd',
    correlationId: 'c',
    operator: 'user:x',
    approvalId: 'abc',
  })
  // The header is what makes `@cloudsforge/http` willing to retry a POST at all.
  assert.equal(target.hits[0]?.headers['idempotency-key'], 'admin-api:approval:abc')
  assert.equal(target.hits[0]?.headers['x-request-id'], 'c')
})

test('the trial balance reads the cited route with the read credential', async () => {
  target.setBody({ balanced: true, totalAbsoluteDelta: '0' })
  const result = await httpLedgerClient(config()).trialBalance()
  assert.equal(result.balanced, true)
  assert.equal(target.hits[0]?.path, '/trial-balance')
  assert.equal(target.hits[0]?.headers['authorization'], `Bearer ${SERVICE_TOKEN}`)
})

test('every kind this service posts is one the LEDGER will actually accept', () => {
  // ═══════════════════════════════════════════════════════════════════════════════════════════
  // micro-org#424. The ledger's kind vocabulary is closed, and a kind outside it is not recorded
  // and then flagged — `validateEntryRequest` answers `400 invalid_entry` before it opens a
  // transaction, so the entry simply never exists. That is why the two services this has already
  // happened to noticed nothing: `micro-foresight` posted `foresight.settlement_fee` for months
  // and no settlement fee was ever booked, and `micro-tessera` posted `item_issue` while the set
  // did not yet contain it, so no object ever entered the ledger (micro-org#407 §3).
  //
  // MEMBERSHIP is the assertion, not spelling, and the value under test is the one the executor
  // actually sends — `ENGAGEMENT_TRANSFER_KIND` is imported here and imported by `actions.ts`.
  // A test that re-spelled the literal would agree with itself and prove nothing about the entry.
  // `PostEntryRequest.kind` is `EntryKind`, so a new call site inventing one is now a compile
  // error; this is the belt to that brace, and the thing that keeps working if the type is ever
  // widened back.
  // ═══════════════════════════════════════════════════════════════════════════════════════════
  for (const kind of [ENGAGEMENT_TRANSFER_KIND]) {
    assert.ok(isEntryKind(kind), `${kind} is not in the ledger's closed set`)
    assert.ok(ENTRY_KINDS.includes(kind), `${kind} is not in ENTRY_KINDS`)
  }
})

/* ------------------------------------------------------------------ market */

test('THE MARKET CALL FORWARDS THE OPERATOR\'S OWN BEARER', async () => {
  // SD-11: nimbus's admin proxies forward the operator's bearer rather than a service secret,
  // "which is a genuinely good decision: Pay and custody record WHICH administrator acted".
  // market/src/server.ts derives `resolvedBy` from the principal, so this is what makes it true.
  target.setBody({ case: { id: 'case-3', state: 'upheld' } })
  await httpMarketClient(config()).resolveCase({
    caseId: 'case-3',
    state: 'upheld',
    notes: 'fraud_response: scam listing',
    correlationId: 'req-2',
    operatorBearer: OPERATOR_BEARER,
  })

  const hit = target.hits[0]!
  assert.equal(hit.path, '/v1/moderation/cases/case-3/resolve')
  assert.equal(hit.headers['authorization'], `Bearer ${OPERATOR_BEARER}`)
  assert.notEqual(hit.headers['authorization'], `Bearer ${SERVICE_TOKEN}`)
  const body = JSON.parse(hit.body)
  assert.equal(body.state, 'upheld')
  assert.equal(body.notes, 'fraud_response: scam listing')
  // `resolvedBy` must NOT be sent: market ignores it and derives the operator from the token, and
  // a client that sent one would look as though it could name anybody.
  assert.equal(body.resolvedBy, undefined)
})

test('the open-case read is a filtered GET on the cited route', async () => {
  target.setBody({ cases: [{ id: 'case-1', state: 'open' }] })
  const cases = await httpMarketClient(config()).openCases(OPERATOR_BEARER)
  assert.equal(cases.length, 1)
  assert.equal(target.hits[0]?.path, '/v1/moderation/cases?state=open')
})

test('a market answer with no cases array reads as empty, not as a crash', async () => {
  target.setBody({})
  assert.deepEqual(await httpMarketClient(config()).openCases(OPERATOR_BEARER), [])
})

/* ------------------------------------------------------------------ billing */

test('the entitlement revocation forwards the operator bearer and the cited body', async () => {
  target.setBody({ alreadyRevoked: false, reversalEntryId: 'entry-refund-1' })
  const result = await httpBillingClient(config()).revokeEntitlement({
    entitlementId: 'ent-9',
    reason: 'chargeback received',
    refund: true,
    correlationId: 'req-3',
    operatorBearer: OPERATOR_BEARER,
  })
  assert.equal(result.reversalEntryId, 'entry-refund-1')
  const hit = target.hits[0]!
  assert.equal(hit.path, '/entitlements/ent-9/revoke')
  assert.equal(hit.headers['authorization'], `Bearer ${OPERATOR_BEARER}`)
  const body = JSON.parse(hit.body)
  assert.equal(body.reason, 'chargeback received')
  assert.equal(body.refund, true)
})

/* ------------------------------------------------------------------ failure shapes */

test('a 4xx is peerDecided; a transport failure is not', async () => {
  target.setStatus(409)
  await assert.rejects(
    async () => httpLedgerClient(config()).trialBalance(),
    (err: unknown) => {
      assert.ok(err instanceof UpstreamError)
      assert.equal(err.status, 409)
      assert.equal(err.peerDecided, true, 'retrying a 4xx produces the same answer')
      return true
    },
  )
})

test('a 5xx is not peerDecided — we do not know what happened', async () => {
  target.setStatus(500)
  await assert.rejects(
    async () => httpLedgerClient(config({ deadlineMs: 300 })).trialBalance(),
    (err: unknown) => {
      assert.ok(err instanceof UpstreamError)
      assert.equal(err.peerDecided, false)
      return true
    },
  )
})

test('an unreachable peer is a null status', async () => {
  const dead = httpLedgerClient({ ...config(), baseUrl: 'http://127.0.0.1:1' })
  await assert.rejects(
    async () => dead.trialBalance(),
    (err: unknown) => {
      assert.ok(err instanceof UpstreamError)
      assert.equal(err.status, null)
      assert.equal(err.peerDecided, false)
      return true
    },
  )
})

test('A WEDGED UPSTREAM IS BOUNDED BY THE DEADLINE, not left hanging', async () => {
  // The socket is accepted and then nothing is written, which is what a wedged upstream actually
  // looks like — a genuinely different failure from a refused connection, and the one that pins a
  // caller indefinitely if there is no total-request timeout. Nimbus's admin proxies call bare
  // `fetch` (routes/vault.ts, routes/pay.ts) and have exactly that hole.
  target.hang(true)
  const started = Date.now()
  await assert.rejects(async () => httpLedgerClient(config({ deadlineMs: 250 })).trialBalance(), UpstreamError)
  assert.ok(Date.now() - started < 3_000, 'the deadline must bound the wait')
})

test('AN UPSTREAM ERROR BODY NEVER REACHES THIS SERVICE\'S ERROR MESSAGE', async () => {
  // An upstream's error body can carry a subject's email or a listing's private terms, and this
  // string is rendered in an operator console and written into logs with a wider audience.
  target.setStatus(400)
  target.setBody({ error: { message: 'user alice@example.com is not entitled' } })
  await assert.rejects(
    async () => httpBillingClient(config()).revokeEntitlement({
      entitlementId: 'e',
      reason: 'r',
      refund: false,
      correlationId: 'c',
      operatorBearer: OPERATOR_BEARER,
    }),
    (err: unknown) => {
      assert.ok(err instanceof UpstreamError)
      assert.equal(err.message, 'billing answered 400')
      assert.ok(!err.message.includes('alice@example.com'))
      return true
    },
  )
})

/* ------------------------------------------------------------------ readiness */

test('a 503 from /readyz is an ANSWER, not a failure', async () => {
  // `/readyz` returning 503 is the endpoint working correctly on a service that is not ready.
  // Treating it as a fault is how an operator console shows "unknown" for a service that is
  // clearly and correctly telling everyone it is unwell.
  target.setStatus(503)
  target.setBody({ ready: false, state: 'degraded', checks: [{ name: 'postgres', state: 'fail' }] })
  const snapshot = await probeReadiness('ledger', config())
  assert.equal(snapshot.ready, false)
  assert.equal(snapshot.state, 'degraded')
  assert.match(snapshot.detail ?? '', /postgres/)
})

test('a healthy /readyz reads as ready with no detail', async () => {
  target.setBody({ ready: true, state: 'ready', checks: [{ name: 'postgres', state: 'pass' }] })
  const snapshot = await probeReadiness('ledger', config())
  assert.equal(snapshot.ready, true)
  assert.equal(snapshot.detail, null)
})

test('a soft-failing check is named even when the service is still ready', async () => {
  target.setBody({
    ready: true,
    state: 'degraded',
    checks: [{ name: 'postgres', state: 'pass' }, { name: 'indexer', state: 'warn' }],
  })
  const snapshot = await probeReadiness('ledger', config())
  assert.equal(snapshot.ready, true)
  assert.match(snapshot.detail ?? '', /indexer/)
})

test('a /readyz that is not JSON is an error, not a guess', async () => {
  target.setBody('not json at all')
  // `setBody` stringifies, so send raw text by making the target answer a bare string body.
  await assert.rejects(async () => {
    const res = await probeReadiness('ledger', {
      ...config(),
      fetch: async () => new Response('<html>502 Bad Gateway</html>', { status: 502 }),
    })
    return res
  }, /not JSON/)
})

test('an unreachable /readyz throws rather than reporting a confident "not ready"', async () => {
  await assert.rejects(
    async () => probeReadiness('ledger', { ...config(), baseUrl: 'http://127.0.0.1:1' }),
    (err: unknown) => {
      assert.ok(err instanceof UpstreamError)
      assert.equal(err.status, null)
      return true
    },
  )
})
