/**
 * The engagement treasury — docs/ecosystem/21, phase 1 — proven the way §7 demands: against the
 * SCHEMA, with raw SQL and a bare connection, before any route is trusted.
 *
 * The proofs from 21 §7 that live in this file:
 *
 *   §7.3  A transfer above a policy cap is refused by the schema, even for a caller holding a
 *         connection — `fire-tested` below by inserting straight into `engagement_transfers`.
 *   §7.4  Every engagement transfer resolves to a ledger entry; a `posted` row with no entry id
 *         cannot exist, and one approval is one transfer for ever.
 *   §7.5  The fee-recycle percentage cannot exceed its schema ceiling.
 *   §7.7  Raising any cap without an approval is refused; lowering without one succeeds — proven
 *         at the trigger with raw SQL AND at the routes (PUT lowers, the queue raises).
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { READ_SCOPE } from './scopes.ts'
import {
  FEE_RECYCLE_CEILING_BPS,
  SEED_PER_DAY_CEILING_WEI,
  SEED_PER_MARKET_CEILING_WEI,
  TRANSFER_CAP_CEILING_SHARDS,
} from './engagement.ts'
import {
  ALICE,
  BOB,
  CAROL,
  enabled,
  fakeVerifier,
  freshKey,
  migrateTestDb,
  openDb,
  operatorPrincipal,
  playerPrincipal,
  resetAdminApi,
  servicePrincipal,
  skip,
  startHarness,
  type FakeVerifier,
  type Harness,
} from './testsupport.ts'

const ONE = 'operator-one-bearer'
const TWO = 'operator-two-bearer'
const PLAYER = 'ordinary-player-bearer'
const READER = 'reader-service-bearer'

const sql = enabled ? openDb() : null
let harness: Harness | null = null
let verifier: FakeVerifier | null = null

before(async () => {
  if (!sql) return
  await migrateTestDb(sql)
  verifier = fakeVerifier({
    [ONE]: operatorPrincipal(ALICE),
    [TWO]: operatorPrincipal(BOB),
    [PLAYER]: playerPrincipal(CAROL),
    [READER]: servicePrincipal('lantern', [READ_SCOPE]),
  })
  harness = await startHarness(sql, verifier)
})
beforeEach(async () => {
  if (sql) await resetAdminApi(sql)
  harness?.reset()
})
after(async () => {
  await harness?.close()
  if (sql) await sql.end({ timeout: 5 })
})

const h = (): Harness => harness!

/* ------------------------------------------------------------------ raw-SQL scaffolding */

/**
 * An approvals row in `approved`, written directly — these fire-tests are ABOUT the caller with
 * a connection, so the scaffolding uses one too. Two distinct operators, per the constraints the
 * approvals migration already enforces.
 */
async function approvedApproval(action: string, state = 'approved'): Promise<string> {
  const rows = await sql!<{ id: string }[]>`
    insert into approvals (
      action, subject_kind, subject_id, params, reason_code, reason,
      requested_by, expires_at, state, decided_by, decided_at
    ) values (
      ${action}, 'engagement_account', 'engagement:foresight', '{}'::jsonb,
      'incident_remediation', 'fire-test scaffolding',
      ${'user:' + ALICE}, now() + interval '1 hour',
      ${state},
      ${state === 'pending' ? null : 'user:' + BOB},
      ${state === 'pending' ? null : sql!`now()`}
    ) returning id
  `
  return rows[0]!.id
}

/** A policy row for foresight, written through the trigger with a real approval behind it. */
async function policyRow(capShards: string, seeds?: { perMarket: string; perDay: string }): Promise<string> {
  const approvalId = await approvedApproval('engagement.policy.set')
  await sql!`
    insert into engagement_policies (
      service, transfer_cap_shards, seed_per_market_wei, seed_per_day_wei,
      last_change_approval_id, updated_by
    ) values (
      'foresight', ${capShards}, ${seeds?.perMarket ?? null}, ${seeds?.perDay ?? null},
      ${approvalId}, ${'user:' + ALICE}
    )
  `
  return approvalId
}

/* ------------------------------------------------------------------ §7.3 — the cap, fire-tested */

test('a transfer above the policy cap is refused by the schema, connection in hand', { skip }, async () => {
  await policyRow('1000')
  const approvalId = await approvedApproval('engagement.transfer')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_shards, approval_id)
      values ('foresight', 1001, ${approvalId})
    `,
    /exceeds the policy cap/,
  )
  // And at the cap it goes through — the cap is a bound, not a taunt.
  await sql!`
    insert into engagement_transfers (service, amount_shards, approval_id)
    values ('foresight', 1000, ${approvalId})
  `
})

test('a transfer to a service with no policy row is refused — the caps must exist first (21 §8)', { skip }, async () => {
  const approvalId = await approvedApproval('engagement.transfer')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_shards, approval_id)
      values ('foresight', 1, ${approvalId})
    `,
    /no engagement policy exists|foreign key/,
  )
})

test('a transfer whose approval is not an approved engagement.transfer is refused by the trigger', { skip }, async () => {
  await policyRow('1000')
  const pending = await approvedApproval('engagement.transfer', 'pending')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_shards, approval_id)
      values ('foresight', 1, ${pending})
    `,
    /not an approved engagement.transfer/,
  )
  const wrongAction = await approvedApproval('ledger.entry.reverse')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_shards, approval_id)
      values ('foresight', 1, ${wrongAction})
    `,
    /not an approved engagement.transfer/,
  )
})

/* ------------------------------------------------------------------ §7.4 — the pairing */

test('a posted transfer names its ledger entry, or it cannot be written', { skip }, async () => {
  await policyRow('1000')
  const approvalId = await approvedApproval('engagement.transfer')
  await sql!`
    insert into engagement_transfers (service, amount_shards, approval_id)
    values ('foresight', 5, ${approvalId})
  `
  // 'posted' with no entry id — the row 21 §7.4 says cannot exist.
  await assert.rejects(
    sql!`update engagement_transfers set state = 'posted' where approval_id = ${approvalId}`,
    /engagement_transfers_posted_names_entry/,
  )
  // An entry id with no 'posted' is equally unwritable: the pairing is an equality, not a hint.
  await assert.rejects(
    sql!`update engagement_transfers set ledger_entry_id = 'entry-9' where approval_id = ${approvalId}`,
    /engagement_transfers_posted_names_entry/,
  )
})

test('one approval is one transfer, for ever', { skip }, async () => {
  await policyRow('1000')
  const approvalId = await approvedApproval('engagement.transfer')
  await sql!`
    insert into engagement_transfers (service, amount_shards, approval_id)
    values ('foresight', 5, ${approvalId})
  `
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_shards, approval_id)
      values ('foresight', 5, ${approvalId})
    `,
    /engagement_transfers_one_per_approval/,
  )
})

/* ------------------------------------------------------------------ §7.5 and the other ceilings */

test('the fee-recycle percentage cannot exceed its schema ceiling', { skip }, async () => {
  const approvalId = await approvedApproval('engagement.policy.set')
  await assert.rejects(
    sql!`
      insert into engagement_fee_recycle (singleton, recycle_bps, last_change_approval_id, updated_by)
      values (true, ${FEE_RECYCLE_CEILING_BPS + 1}, ${approvalId}, ${'user:' + ALICE})
      on conflict (singleton) do update set
        recycle_bps = excluded.recycle_bps,
        last_change_approval_id = excluded.last_change_approval_id
    `,
    /engagement_fee_recycle_within_ceiling/,
  )
})

test('every ceiling constant matches its constraint — proven by writing ceiling-plus-one', { skip }, async () => {
  const approvalId = await approvedApproval('engagement.policy.set')
  await assert.rejects(
    sql!`
      insert into engagement_policies (service, transfer_cap_shards, last_change_approval_id, updated_by)
      values ('market', ${(TRANSFER_CAP_CEILING_SHARDS + 1n).toString()}, ${approvalId}, ${'user:' + ALICE})
    `,
    /engagement_policies_cap_within_ceiling/,
  )
  await assert.rejects(
    sql!`
      insert into engagement_policies (
        service, transfer_cap_shards, seed_per_market_wei, seed_per_day_wei,
        last_change_approval_id, updated_by
      ) values (
        'foresight', 0, ${(SEED_PER_MARKET_CEILING_WEI + 1n).toString()},
        ${SEED_PER_DAY_CEILING_WEI.toString()}, ${approvalId}, ${'user:' + ALICE}
      )
    `,
    /engagement_policies_seed_within_ceiling/,
  )
  // Seeds belong to foresight alone; another service carrying them is refused.
  await assert.rejects(
    sql!`
      insert into engagement_policies (
        service, transfer_cap_shards, seed_per_market_wei, seed_per_day_wei,
        last_change_approval_id, updated_by
      ) values ('trade', 0, 1, 1, ${approvalId}, ${'user:' + ALICE})
    `,
    /engagement_policies_seeds_are_foresights/,
  )
})

/* ------------------------------------------------------------------ §7.7 — the asymmetry, at the trigger */

test('raising a cap by raw SQL without a fresh approval is refused; lowering succeeds', { skip }, async () => {
  const approvalId = await policyRow('1000')
  // LOWER, no new approval: succeeds. The operator narrowing blast radius needs nobody's
  // counter-signature.
  await sql!`update engagement_policies set transfer_cap_shards = 500 where service = 'foresight'`
  // RAISE reusing the SAME approval id: refused — one approval does not authorise unlimited
  // later raises.
  await assert.rejects(
    sql!`update engagement_policies set transfer_cap_shards = 900 where service = 'foresight'`,
    /raising an engagement cap requires a fresh approved/,
  )
  // RAISE naming a fresh but PENDING approval: refused.
  const pending = await approvedApproval('engagement.policy.set', 'pending')
  await assert.rejects(
    sql!`
      update engagement_policies
         set transfer_cap_shards = 900, last_change_approval_id = ${pending}
       where service = 'foresight'
    `,
    /not an approved engagement.policy.set/,
  )
  // RAISE naming a fresh APPROVED approval: succeeds. The asymmetry is a gate, not a wall.
  const fresh = await approvedApproval('engagement.policy.set')
  await sql!`
    update engagement_policies
       set transfer_cap_shards = 900, last_change_approval_id = ${fresh}
     where service = 'foresight'
  `
  assert.notEqual(approvalId, fresh)
})

/* ------------------------------------------------------------------ the routes: raise via the queue */

async function requestAction(
  token: string,
  action: string,
  params: Record<string, unknown>,
  subjectId = 'engagement:foresight',
): Promise<{ status: number; body: any }> {
  return h().request('POST', '/v1/approvals', {
    token,
    headers: { 'idempotency-key': freshKey() },
    body: {
      action,
      subjectId,
      params,
      reasonCode: 'incident_remediation',
      reason: 'seeding the foresight cold start (21 §5)',
    },
  })
}

async function decide(token: string, id: string, grant = true): Promise<{ status: number; body: any }> {
  return h().request('POST', `/v1/approvals/${id}/decision`, {
    token,
    headers: { 'idempotency-key': freshKey() },
    body: { grant },
  })
}

test('a cap is raised through the queue: two operators, then the policy row exists', { skip }, async () => {
  const raised = await requestAction(ONE, 'engagement.policy.set', {
    service: 'foresight',
    transferCapShards: '1000',
    seedPerMarketWei: '1000000000000000000',
    seedPerDayWei: '5000000000000000000',
  })
  assert.equal(raised.status, 201)
  const approvalId = raised.body.approval.id

  const decided = await decide(TWO, approvalId)
  assert.equal(decided.status, 201)
  assert.equal(decided.body.approval.executionOutcome, 'succeeded')
  assert.equal(decided.body.execution.policy.transferCapShards, '1000')

  const policies = await h().request('GET', '/v1/engagement/policies', { token: ONE })
  assert.equal(policies.status, 200)
  const foresight = policies.body.policies.find((p: any) => p.service === 'foresight')
  assert.equal(foresight.transferCapShards, '1000')
  assert.equal(foresight.seedPerMarketWei, '1000000000000000000')
  assert.equal(foresight.lastChangeApprovalId, approvalId)
  // The ceilings ride along so a console renders the bounds.
  assert.equal(policies.body.ceilings.transferCapShards, TRANSFER_CAP_CEILING_SHARDS.toString())
})

test('the fee recycle is raised through the queue under service "platform"', { skip }, async () => {
  const raised = await requestAction(ONE, 'engagement.policy.set', { service: 'platform', recycleBps: '250' }, 'fee-recycle')
  assert.equal(raised.status, 201)
  const decided = await decide(TWO, raised.body.approval.id)
  assert.equal(decided.status, 201)
  assert.equal(decided.body.execution.feeRecycle.recycleBps, 250)

  // And lowering it back needs one operator, no queue.
  const lowered = await h().request('PUT', '/v1/engagement/policies/platform', {
    token: ONE,
    body: { recycleBps: '0' },
  })
  assert.equal(lowered.status, 200)
  assert.equal(lowered.body.feeRecycle.recycleBps, 0)
})

/* ------------------------------------------------------------------ §7.7 at the routes */

test('PUT lowers without a queue; PUT refuses a raise and names the action — the devplatform asymmetry', { skip }, async () => {
  const raised = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapShards: '1000' })
  await decide(TWO, raised.body.approval.id)

  const lowered = await h().request('PUT', '/v1/engagement/policies/foresight', {
    token: ONE,
    body: { transferCapShards: '400' },
  })
  assert.equal(lowered.status, 200)
  assert.equal(lowered.body.policy.transferCapShards, '400')

  const raise = await h().request('PUT', '/v1/engagement/policies/foresight', {
    token: ONE,
    body: { transferCapShards: '2000' },
  })
  assert.equal(raise.status, 403)
  assert.equal(raise.body.error.code, 'raise_needs_approval')
  assert.match(raise.body.error.message, /engagement\.policy\.set/)
})

test('a service token cannot lower a cap — an operator surface admits operators', { skip }, async () => {
  const res = await h().request('PUT', '/v1/engagement/policies/foresight', {
    token: READER,
    body: { transferCapShards: '0' },
  })
  assert.equal(res.status, 403)
})

/* ------------------------------------------------------------------ the transfer, end to end */

test('an approved transfer posts ONE balanced ledger entry and records the pairing', { skip }, async () => {
  const capRaise = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapShards: '1000' })
  await decide(TWO, capRaise.body.approval.id)

  const transfer = await requestAction(ONE, 'engagement.transfer', { service: 'foresight', amountShards: '600' })
  assert.equal(transfer.status, 201)
  const decided = await decide(TWO, transfer.body.approval.id)
  assert.equal(decided.status, 201)
  assert.equal(decided.body.approval.executionOutcome, 'succeeded')
  assert.equal(decided.body.execution.amountShards, '600')
  assert.ok(decided.body.execution.ledgerEntryId)

  // Exactly one entry, debit treasury → credit engagement:foresight, in Shards, both accounts
  // inline so the ledger creates them idempotently on first use.
  assert.equal(h().ledger.entries.length, 1)
  const entry = h().ledger.entries[0]!
  assert.equal(entry.kind, 'transfer')
  assert.equal(entry.idempotencyKey, `admin-api:approval:${transfer.body.approval.id}`)
  assert.deepEqual(
    entry.postings.map((p) => [p.direction, p.account.subject, p.amount, p.assetCode]),
    [
      ['debit', 'platform:engagement-treasury', '600', 'SHARD'],
      ['credit', 'engagement:foresight', '600', 'SHARD'],
    ],
  )

  const report = await h().request('GET', '/v1/engagement/report', { token: READER })
  assert.equal(report.status, 200)
  assert.equal(report.body.spendShardsByService.foresight, '600')
  assert.equal(report.body.transfers[0].state, 'posted')
  assert.equal(report.body.transfers[0].ledgerEntryId, 'posted-1')
})

test('a transfer above the cap — or with no cap — is refused at REQUEST time, before a signature is spent', { skip }, async () => {
  const uncapped = await requestAction(ONE, 'engagement.transfer', { service: 'foresight', amountShards: '1' })
  assert.equal(uncapped.status, 400)
  assert.match(uncapped.body.error.message, /no engagement policy exists/)

  const capRaise = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapShards: '100' })
  await decide(TWO, capRaise.body.approval.id)

  const over = await requestAction(ONE, 'engagement.transfer', { service: 'foresight', amountShards: '101' })
  assert.equal(over.status, 400)
  assert.match(over.body.error.message, /exceeds engagement:foresight/)
})

/* ------------------------------------------------------------------ the read action and the report */

test('engagement.report is refused by the queue and the refusal names the GET — 21 §6 "none (read)"', { skip }, async () => {
  const res = await requestAction(ONE, 'engagement.report', {})
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /GET \/v1\/engagement\/report/)
})

test('the report reads balances off the ledger for the treasury and every policy row', { skip }, async () => {
  const capRaise = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapShards: '100' })
  await decide(TWO, capRaise.body.approval.id)
  h().ledger.setBalances('platform:engagement-treasury', [
    { subject: 'platform:engagement-treasury', assetCode: 'SHARD', purpose: 'treasury', type: 'equity', status: 'open', amount: '5000' },
  ])
  h().ledger.setBalances('engagement:foresight', [
    { subject: 'engagement:foresight', assetCode: 'SHARD', purpose: 'treasury', type: 'equity', status: 'open', amount: '100' },
  ])

  const report = await h().request('GET', '/v1/engagement/report', { token: ONE })
  assert.equal(report.status, 200)
  assert.equal(report.body.treasury.balances[0].amount, '5000')
  assert.equal(report.body.services[0].service, 'foresight')
  assert.equal(report.body.services[0].balances[0].amount, '100')
  assert.equal(report.body.feeRecycle.recycleBps, 0)

  // And a player token reads nothing here.
  const refusedRead = await h().request('GET', '/v1/engagement/report', { token: PLAYER })
  assert.equal(refusedRead.status, 403)
})
