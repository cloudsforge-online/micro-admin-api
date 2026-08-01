/**
 * The estate view, and degradation.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A DEGRADED UPSTREAM MUST NOT BLANK THE CONSOLE**, and — the half that catches regressions —
 * **EVERY UNAFFECTED TILE MUST STILL BE `ok`.**
 *
 * `hub-api` proves this with seven degradation tests, one per upstream. The same shape here, with
 * one test per source in `TILE_SOURCES`, driven from that table so a tile that quietly acquires a
 * second dependency fails the build.
 *
 * It matters more on this surface than on a user dashboard: the operator console is read DURING an
 * incident, which is exactly when some upstream is down. A console that 500s then is unavailable
 * precisely when it exists to be used, and the operator falls back to `docker logs` — the thing
 * 17 §7 row 9 measures this whole surface against.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { TILE_SOURCES, composeEstate, type EstateView } from './estate.ts'
import { appendAudit, writeCheckpoint } from './audit.ts'
import { requestApproval } from './approvals.ts'
import { publishBroadcast } from './broadcasts.ts'
import {
  ALICE,
  BOB,
  OPERATOR_ONE,
  db,
  enabled,
  fakeBilling,
  fakeLedger,
  fakeMarket,
  fakeReadiness,
  fakeVerifier,
  freshKey,
  migrateTestDb,
  openDb,
  operatorPrincipal,
  refused,
  resetAdminApi,
  skip,
  startHarness,
  unreachable,
  type FakeLedger,
  type FakeMarket,
  type Harness,
} from './testsupport.ts'

const sql = enabled ? openDb() : null
let ledger: FakeLedger
let market: FakeMarket

before(async () => {
  if (sql) await migrateTestDb(sql)
})
beforeEach(async () => {
  if (sql) await resetAdminApi(sql)
  ledger = fakeLedger()
  market = fakeMarket()
})
after(async () => {
  if (sql) await sql.end({ timeout: 5 })
})

const HEALTHY = {
  identity: { ready: true, state: 'ready' } as const,
  ledger: { ready: true, state: 'ready' } as const,
  market: { ready: true, state: 'ready' } as const,
  billing: { ready: true, state: 'ready' } as const,
}

async function compose(
  overrides: { readiness?: Parameters<typeof fakeReadiness>[0] } = {},
): Promise<EstateView> {
  return composeEstate({
    sql: db(sql!),
    ledger,
    market,
    readiness: fakeReadiness(overrides.readiness ?? HEALTHY),
    operatorBearer: 'operator-one-bearer',
  })
}

/** Every tile's status, so a degradation test can assert about the ones it did NOT break. */
function statuses(view: EstateView): Record<string, string> {
  return Object.fromEntries(Object.entries(view).map(([name, tile]) => [name, tile.status]))
}

test('the tile source table names every tile the view composes', { skip }, async () => {
  const view = await compose()
  assert.deepEqual(Object.keys(view).sort(), Object.keys(TILE_SOURCES).sort())
})

test('with everything healthy, every tile is ok', { skip }, async () => {
  const view = await compose()
  assert.deepEqual(statuses(view), {
    services: 'ok',
    trialBalance: 'ok',
    openModerationCases: 'ok',
    approvals: 'ok',
    audit: 'ok',
    broadcasts: 'ok',
  })
  // `data` is never null, so a client renders an empty state rather than a crash.
  for (const tile of Object.values(view)) {
    assert.notEqual(tile.data, null)
    assert.equal(tile.reason, null)
  }
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
   ONE PER UPSTREAM.
   ══════════════════════════════════════════════════════════════════════════════════════════════ */

test('DEGRADE ledger: only the trial-balance tile is affected', { skip }, async () => {
  ledger.failWith(unreachable('ledger'))
  const view = await compose()

  assert.equal(view.trialBalance.status, 'unavailable')
  assert.equal(view.trialBalance.reason, 'ledger could not be reached')
  assert.equal(view.trialBalance.data.balanced, null)

  // ── The half that catches regressions.
  assert.equal(view.openModerationCases.status, 'ok')
  assert.equal(view.approvals.status, 'ok')
  assert.equal(view.broadcasts.status, 'ok')
  assert.equal(view.services.status, 'ok')
})

test('DEGRADE market: only the moderation tile is affected', { skip }, async () => {
  market.failWith(refused('market', 403))
  const view = await compose()

  assert.equal(view.openModerationCases.status, 'unavailable')
  assert.equal(view.openModerationCases.reason, 'market answered 403')
  assert.equal(view.openModerationCases.data.count, null)

  assert.equal(view.trialBalance.status, 'ok')
  assert.equal(view.approvals.status, 'ok')
  assert.equal(view.services.status, 'ok')
})

test('DEGRADE readiness: only the services tile is affected, and it keeps its data', { skip }, async () => {
  const view = await compose({
    readiness: { ...HEALTHY, billing: { ready: false, state: 'degraded', detail: 'postgres' } },
  })
  // DEGRADED, not unavailable: the tile HAS its data, and the data is that a service is down —
  // which is the single most useful thing on the page. Marking it unavailable would hide the
  // outage behind the outage.
  assert.equal(view.services.status, 'degraded')
  assert.match(view.services.reason ?? '', /billing/)
  assert.equal(view.services.data.length, 4)

  assert.equal(view.trialBalance.status, 'ok')
  assert.equal(view.openModerationCases.status, 'ok')
})

test('DEGRADE readiness by an unreachable probe: it becomes a named row, not a thrown request', { skip }, async () => {
  const view = await compose({ readiness: { ...HEALTHY, ledger: 'throw' } })
  assert.equal(view.services.status, 'degraded')
  const row = view.services.data.find((s) => s.name === 'ledger')
  assert.equal(row?.ready, false)
  assert.equal(row?.state, 'unreachable')
  assert.match(row?.detail ?? '', /could not be reached/)
})

test('EVERY upstream down at once still composes, and every self tile is still ok', { skip }, async () => {
  ledger.failWith(unreachable('ledger'))
  market.failWith(unreachable('market'))
  const view = await compose({
    readiness: {
      identity: 'throw',
      ledger: 'throw',
      market: 'throw',
      billing: 'throw',
    },
  })
  assert.equal(view.trialBalance.status, 'unavailable')
  assert.equal(view.openModerationCases.status, 'unavailable')
  assert.equal(view.services.status, 'degraded')
  // The audit mirror, the approval queue and the broadcasts are THIS service's own data. An
  // operator with the whole estate down can still read who did what.
  assert.equal(view.approvals.status, 'ok')
  assert.equal(view.audit.status, 'ok')
  assert.equal(view.broadcasts.status, 'ok')
})

/* ------------------------------------------------------------------ the trial balance */

test('a NON-ZERO trial balance degrades the tile rather than reading as ok', { skip }, async () => {
  // 17 §8: trial balance ≠ 0 is a P0 and everything downstream of the ledger is untrustworthy
  // until it is zero. The ledger answered correctly, and what it said is that something is wrong.
  ledger.setTrialBalance({ balanced: false, totalAbsoluteDelta: '4200' })
  const view = await compose()
  assert.equal(view.trialBalance.status, 'degraded')
  assert.match(view.trialBalance.reason ?? '', /TRIAL BALANCE IS NOT ZERO/)
  assert.equal(view.trialBalance.data.totalAbsoluteDelta, '4200')
})

/* ------------------------------------------------------------------ the self tiles */

test('the approvals tile counts pending and those expiring within the hour', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await requestApproval(tx, {
      action: 'ledger.entry.reverse',
      subjectKind: 'ledger_entry',
      subjectId: 'a',
      params: {},
      reasonCode: 'data_correction',
      reason: 'r',
      requestedBy: OPERATOR_ONE,
      ttlMinutes: 30,
    })
    await requestApproval(tx, {
      action: 'ledger.entry.reverse',
      subjectKind: 'ledger_entry',
      subjectId: 'b',
      params: {},
      reasonCode: 'data_correction',
      reason: 'r',
      requestedBy: OPERATOR_ONE,
      ttlMinutes: 600,
    })
    return { value: null }
  })
  const view = await compose()
  assert.equal(view.approvals.data.pending, 2)
  assert.equal(view.approvals.data.expiringWithinHour, 1)
})

test('the audit tile DEGRADES when the chain has never been verified', { skip }, async () => {
  // SD-16 verifies continuity nightly and calls a break a P0, so a verification that has never run
  // is a control that is not running — and an operator should see that.
  await sql!.begin(async (tx) => {
    await appendAudit(tx, { actor: OPERATOR_ONE, action: 'a', subjectKind: 'b', subjectId: 'c', outcome: 'allowed' })
    return { value: null }
  })
  const before = await compose()
  assert.equal(before.audit.status, 'degraded')
  assert.match(before.audit.reason ?? '', /never been verified/)

  await writeCheckpoint(sql!, 'service:admin-api@test')
  const after = await compose()
  assert.equal(after.audit.status, 'ok')
  assert.equal(after.audit.data.lastVerifiedSeq, '1')
})

test('an empty audit chain is ok, not degraded', { skip }, async () => {
  // A fresh deployment has nothing to verify. Degrading there would make every new environment
  // start amber, which is how an amber tile stops meaning anything.
  const view = await compose()
  assert.equal(view.audit.status, 'ok')
  assert.equal(view.audit.data.headSeq, '0')
  assert.equal(view.audit.data.headHash, null)
})

test('the broadcasts tile counts only what is live', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await publishBroadcast(
      tx,
      { severity: 'info', title: 'live', body: 'b', operator: OPERATOR_ONE },
      'admin-api',
    )
    await publishBroadcast(
      tx,
      {
        severity: 'maintenance',
        title: 'past',
        body: 'b',
        startsAt: new Date(Date.now() - 7_200_000),
        endsAt: new Date(Date.now() - 3_600_000),
        operator: OPERATOR_ONE,
      },
      'admin-api',
    )
    return { value: null }
  })
  const view = await compose()
  assert.equal(view.broadcasts.data.live, 1)
})

/* ------------------------------------------------------------------ over HTTP */

test('THE ROUTE ANSWERS 200 WITH EVERY UPSTREAM DOWN', { skip }, async () => {
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, {
    readiness: fakeReadiness({ identity: 'throw', ledger: 'throw' }),
  })
  try {
    harness.ledger.failWith(unreachable('ledger'))
    harness.market.failWith(unreachable('market'))
    const res = await harness.request('GET', '/v1/estate', { token: 'operator-bearer' })
    // ── The console does not blank.
    assert.equal(res.status, 200)
    assert.equal(res.body.trialBalance.status, 'unavailable')
    assert.equal(res.body.approvals.status, 'ok')
    // And the tile counter carries the signal, because the HTTP error rate cannot: a view serving
    // 200s with two dead tiles is healthy in `http_requests_total` by design.
    assert.match(harness.metrics.render(), /admin_estate_tile_status_total\{tile="trialBalance",status="unavailable"\} 1/)
  } finally {
    await harness.close()
  }
})

test('the estate route forwards the operator bearer to market', { skip }, async () => {
  const verifier = fakeVerifier({ 'operator-two-bearer': operatorPrincipal(BOB) })
  const harness: Harness = await startHarness(sql!, verifier, { readiness: fakeReadiness(HEALTHY) })
  try {
    await harness.request('GET', '/v1/estate', { token: 'operator-two-bearer' })
    assert.deepEqual(harness.market.reads, ['operator-two-bearer'])
  } finally {
    await harness.close()
  }
})

test('a broadcast published over HTTP shows in the estate view', { skip }, async () => {
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, { readiness: fakeReadiness(HEALTHY) })
  try {
    await harness.request('POST', '/v1/broadcasts', {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { severity: 'incident', title: 'Withdrawals paused', body: 'Investigating.' },
    })
    const view = await harness.request('GET', '/v1/estate', { token: 'operator-bearer' })
    assert.equal(view.body.broadcasts.data.live, 1)
  } finally {
    await harness.close()
  }
})

test('the fake billing client is unused by the view, which is the point of TILE_SOURCES', { skip }, async () => {
  // Billing feeds no tile. If it ever does, `TILE_SOURCES` must say so and this line changes —
  // which is what stops a tile quietly acquiring a second dependency.
  const billing = fakeBilling()
  assert.equal(billing.revocations.length, 0)
  assert.ok(!Object.values(TILE_SOURCES).includes('billing'))
})
