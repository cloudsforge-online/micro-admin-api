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
import postgres from 'postgres'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { READ_SCOPE } from './scopes.ts'
import { MIGRATIONS } from './migrations.ts'
import {
  FEE_RECYCLE_CEILING_BPS,
  SEED_PER_DAY_CEILING_WEI,
  SEED_PER_MARKET_CEILING_WEI,
  TRANSFER_CAP_CEILING_WEI,
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

/**
 * A whole number of EMBER, in wei.
 *
 * Every figure in this file is wei since migration 13 (micro-org#226) — `1000` would be a
 * thousandth of a millionth of a cent, which is a bound nobody can read. The helper keeps the
 * numbers the same size they were when they were Shards so the tests still read as money.
 */
const ember = (whole: number): string => (BigInt(whole) * 1_000_000_000_000_000_000n).toString()

/** A policy row for foresight, written through the trigger with a real approval behind it. */
async function policyRow(capWei: string, seeds?: { perMarket: string; perDay: string }): Promise<string> {
  const approvalId = await approvedApproval('engagement.policy.set')
  await sql!`
    insert into engagement_policies (
      service, transfer_cap_wei, seed_per_market_wei, seed_per_day_wei,
      last_change_approval_id, updated_by
    ) values (
      'foresight', ${capWei}, ${seeds?.perMarket ?? null}, ${seeds?.perDay ?? null},
      ${approvalId}, ${'user:' + ALICE}
    )
  `
  return approvalId
}

/* ------------------------------------------------------------------ §7.3 — the cap, fire-tested */

test('a transfer above the policy cap is refused by the schema, connection in hand', { skip }, async () => {
  await policyRow(ember(1000))
  const approvalId = await approvedApproval('engagement.transfer')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_wei, approval_id)
      values ('foresight', ${ember(1001)}, ${approvalId})
    `,
    /exceeds the policy cap/,
  )
  // And at the cap it goes through — the cap is a bound, not a taunt.
  await sql!`
    insert into engagement_transfers (service, amount_wei, approval_id)
    values ('foresight', ${ember(1000)}, ${approvalId})
  `
})

test('a transfer to a service with no policy row is refused — the caps must exist first (21 §8)', { skip }, async () => {
  const approvalId = await approvedApproval('engagement.transfer')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_wei, approval_id)
      values ('foresight', ${ember(1)}, ${approvalId})
    `,
    /no engagement policy exists|foreign key/,
  )
})

test('a transfer whose approval is not an approved engagement.transfer is refused by the trigger', { skip }, async () => {
  await policyRow(ember(1000))
  const pending = await approvedApproval('engagement.transfer', 'pending')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_wei, approval_id)
      values ('foresight', ${ember(1)}, ${pending})
    `,
    /not an approved engagement.transfer/,
  )
  const wrongAction = await approvedApproval('ledger.entry.reverse')
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_wei, approval_id)
      values ('foresight', ${ember(1)}, ${wrongAction})
    `,
    /not an approved engagement.transfer/,
  )
})

/* ------------------------------------------------------------------ §7.4 — the pairing */

test('a posted transfer names its ledger entry, or it cannot be written', { skip }, async () => {
  await policyRow(ember(1000))
  const approvalId = await approvedApproval('engagement.transfer')
  await sql!`
    insert into engagement_transfers (service, amount_wei, approval_id)
    values ('foresight', ${ember(5)}, ${approvalId})
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
  await policyRow(ember(1000))
  const approvalId = await approvedApproval('engagement.transfer')
  await sql!`
    insert into engagement_transfers (service, amount_wei, approval_id)
    values ('foresight', ${ember(5)}, ${approvalId})
  `
  await assert.rejects(
    sql!`
      insert into engagement_transfers (service, amount_wei, approval_id)
      values ('foresight', ${ember(5)}, ${approvalId})
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
      insert into engagement_policies (service, transfer_cap_wei, last_change_approval_id, updated_by)
      values ('market', ${(TRANSFER_CAP_CEILING_WEI + 1n).toString()}, ${approvalId}, ${'user:' + ALICE})
    `,
    /engagement_policies_cap_within_ceiling/,
  )
  await assert.rejects(
    sql!`
      insert into engagement_policies (
        service, transfer_cap_wei, seed_per_market_wei, seed_per_day_wei,
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
        service, transfer_cap_wei, seed_per_market_wei, seed_per_day_wei,
        last_change_approval_id, updated_by
      ) values ('trade', 0, 1, 1, ${approvalId}, ${'user:' + ALICE})
    `,
    /engagement_policies_seeds_are_foresights/,
  )
})

/* ------------------------------------------------------------------ §7.7 — the asymmetry, at the trigger */

test('raising a cap by raw SQL without a fresh approval is refused; lowering succeeds', { skip }, async () => {
  const approvalId = await policyRow(ember(1000))
  // LOWER, no new approval: succeeds. The operator narrowing blast radius needs nobody's
  // counter-signature.
  await sql!`update engagement_policies set transfer_cap_wei = ${ember(500)} where service = 'foresight'`
  // RAISE reusing the SAME approval id: refused — one approval does not authorise unlimited
  // later raises.
  await assert.rejects(
    sql!`update engagement_policies set transfer_cap_wei = ${ember(900)} where service = 'foresight'`,
    /raising an engagement cap requires a fresh approved/,
  )
  // RAISE naming a fresh but PENDING approval: refused.
  const pending = await approvedApproval('engagement.policy.set', 'pending')
  await assert.rejects(
    sql!`
      update engagement_policies
         set transfer_cap_wei = ${ember(900)}, last_change_approval_id = ${pending}
       where service = 'foresight'
    `,
    /not an approved engagement.policy.set/,
  )
  // RAISE naming a fresh APPROVED approval: succeeds. The asymmetry is a gate, not a wall.
  const fresh = await approvedApproval('engagement.policy.set')
  await sql!`
    update engagement_policies
       set transfer_cap_wei = ${ember(900)}, last_change_approval_id = ${fresh}
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
    transferCapWei: ember(1000),
    seedPerMarketWei: '1000000000000000000',
    seedPerDayWei: '5000000000000000000',
  })
  assert.equal(raised.status, 201)
  const approvalId = raised.body.approval.id

  const decided = await decide(TWO, approvalId)
  assert.equal(decided.status, 201)
  assert.equal(decided.body.approval.executionOutcome, 'succeeded')
  assert.equal(decided.body.execution.policy.transferCapWei, ember(1000))

  const policies = await h().request('GET', '/v1/engagement/policies', { token: ONE })
  assert.equal(policies.status, 200)
  const foresight = policies.body.policies.find((p: any) => p.service === 'foresight')
  assert.equal(foresight.transferCapWei, ember(1000))
  assert.equal(foresight.seedPerMarketWei, '1000000000000000000')
  assert.equal(foresight.lastChangeApprovalId, approvalId)
  // The ceilings ride along so a console renders the bounds.
  assert.equal(policies.body.ceilings.transferCapWei, TRANSFER_CAP_CEILING_WEI.toString())
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
  const raised = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapWei: ember(1000) })
  await decide(TWO, raised.body.approval.id)

  const lowered = await h().request('PUT', '/v1/engagement/policies/foresight', {
    token: ONE,
    body: { transferCapWei: ember(400) },
  })
  assert.equal(lowered.status, 200)
  assert.equal(lowered.body.policy.transferCapWei, ember(400))

  const raise = await h().request('PUT', '/v1/engagement/policies/foresight', {
    token: ONE,
    body: { transferCapWei: ember(2000) },
  })
  assert.equal(raise.status, 403)
  assert.equal(raise.body.error.code, 'raise_needs_approval')
  assert.match(raise.body.error.message, /engagement\.policy\.set/)
})

test('a service token cannot lower a cap — an operator surface admits operators', { skip }, async () => {
  const res = await h().request('PUT', '/v1/engagement/policies/foresight', {
    token: READER,
    body: { transferCapWei: '0' },
  })
  assert.equal(res.status, 403)
})

/* ------------------------------------------------------------------ the transfer, end to end */

test('an approved transfer posts ONE balanced ledger entry and records the pairing', { skip }, async () => {
  const capRaise = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapWei: ember(1000) })
  await decide(TWO, capRaise.body.approval.id)

  const transfer = await requestAction(ONE, 'engagement.transfer', { service: 'foresight', amountWei: ember(600) })
  assert.equal(transfer.status, 201)
  const decided = await decide(TWO, transfer.body.approval.id)
  assert.equal(decided.status, 201)
  assert.equal(decided.body.approval.executionOutcome, 'succeeded')
  assert.equal(decided.body.execution.amountWei, ember(600))
  assert.ok(decided.body.execution.ledgerEntryId)

  // Exactly one entry, debit treasury → credit engagement:foresight, in EMBER, both accounts
  // inline so the ledger creates them idempotently on first use.
  assert.equal(h().ledger.entries.length, 1)
  const entry = h().ledger.entries[0]!
  assert.equal(entry.kind, 'transfer')
  assert.equal(entry.idempotencyKey, `admin-api:approval:${transfer.body.approval.id}`)
  assert.deepEqual(
    entry.postings.map((p) => [p.direction, p.account.subject, p.amount, p.assetCode]),
    [
      ['debit', 'platform:engagement-treasury', ember(600), 'EMBER'],
      ['credit', 'engagement:foresight', ember(600), 'EMBER'],
    ],
  )

  const report = await h().request('GET', '/v1/engagement/report', { token: READER })
  assert.equal(report.status, 200)
  assert.equal(report.body.spendWeiByService.foresight, ember(600))
  assert.equal(report.body.transfers[0].state, 'posted')
  assert.equal(report.body.transfers[0].ledgerEntryId, 'posted-1')
})

test('a transfer above the cap — or with no cap — is refused at REQUEST time, before a signature is spent', { skip }, async () => {
  const uncapped = await requestAction(ONE, 'engagement.transfer', { service: 'foresight', amountWei: ember(1) })
  assert.equal(uncapped.status, 400)
  assert.match(uncapped.body.error.message, /no engagement policy exists/)

  const capRaise = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapWei: ember(100) })
  await decide(TWO, capRaise.body.approval.id)

  const over = await requestAction(ONE, 'engagement.transfer', { service: 'foresight', amountWei: ember(101) })
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
  const capRaise = await requestAction(ONE, 'engagement.policy.set', { service: 'foresight', transferCapWei: ember(100) })
  await decide(TWO, capRaise.body.approval.id)
  h().ledger.setBalances('platform:engagement-treasury', [
    { subject: 'platform:engagement-treasury', assetCode: 'EMBER', purpose: 'treasury', type: 'equity', status: 'open', amount: ember(5000) },
  ])
  h().ledger.setBalances('engagement:foresight', [
    { subject: 'engagement:foresight', assetCode: 'EMBER', purpose: 'treasury', type: 'equity', status: 'open', amount: ember(100) },
  ])

  const report = await h().request('GET', '/v1/engagement/report', { token: ONE })
  assert.equal(report.status, 200)
  assert.equal(report.body.treasury.balances[0].amount, ember(5000))
  assert.equal(report.body.services[0].service, 'foresight')
  assert.equal(report.body.services[0].balances[0].amount, ember(100))
  assert.equal(report.body.feeRecycle.recycleBps, 0)

  // And a player token reads nothing here.
  const refusedRead = await h().request('GET', '/v1/engagement/report', { token: PLAYER })
  assert.equal(refusedRead.status, 403)
})

/* --------------------------------------------------- migration 13: Shards become EMBER wei */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE RENAME IS A CONVERSION, AND A CONVERSION HAS TO BE REPLAYED TO BE BELIEVED.**
 *
 * micro-org#226. Every other test in this file runs against a database the migrator brought
 * straight to the head version, so none of them can see the one thing migration 13 does beyond
 * renaming two columns: multiply the Shard-era figures by 4e16, so they mean the same money in a
 * unit with eighteen decimals instead of none.
 *
 * This replays the upgrade — a scratch schema taken to version 12, the rows a pre-#226 database
 * would hold, then 13 applied and the rows read back. On mainnet the same statements touch
 * nothing at all: both tables were measured empty on 2026-08-10 (see migrations.ts), which is
 * what makes a rename legitimate here. A development database that DOES hold Shard figures is
 * the case this proves, and it is the only case anybody can get wrong.
 *
 * The triggers are exercised for a second reason. plpgsql binds record fields LATE, at first
 * execution, so a function body still naming `new.transfer_cap_shards` would survive the whole
 * migration in silence and then raise `record "new" has no field ...` on the first policy write
 * somebody made — a schema error dressed as a runtime one, arriving whenever the next cap change
 * happened rather than at deploy. Recreating a function is only proven by running it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
test('migration 13 converts Shard figures at 4e16 and rebinds the engagement triggers', { skip }, async () => {
  const SCHEMA = 'mig13_replay'
  await sql!.unsafe(`drop schema if exists ${SCHEMA} cascade`)
  await sql!.unsafe(`create schema ${SCHEMA}`)
  // A separate connection whose search_path is the scratch schema: every statement in MIGRATIONS
  // names its tables unqualified, so this is what makes the replay land beside the real schema
  // rather than on top of it.
  const scratch = postgres(process.env['ADMIN_API_TEST_DATABASE_URL']!, {
    max: 1,
    onnotice: () => {},
    connection: { search_path: SCHEMA },
  })
  /** The approval every engagement write has to name, written into the scratch schema. */
  const approval = async (action: string): Promise<string> => {
    const rows = await scratch<{ id: string }[]>`
      insert into approvals (
        action, subject_kind, subject_id, params, reason_code, reason,
        requested_by, expires_at, state, decided_by, decided_at
      ) values (
        ${action}, 'engagement_account', 'engagement:foresight', '{}'::jsonb,
        'incident_remediation', 'migration 13 replay',
        ${'user:' + ALICE}, now() + interval '1 hour', 'approved', ${'user:' + BOB}, now()
      ) returning id
    `
    return rows[0]!.id
  }
  try {
    await migrate(
      scratch as unknown as DbSql,
      MIGRATIONS.filter((m) => m.version <= 12),
      { service: 'admin-api-mig13-replay' },
    )

    // 25 Shards is 25 US cents is 1 EMBER, at the two rates migration 13 freezes.
    await scratch`
      insert into engagement_policies (service, transfer_cap_shards, last_change_approval_id, updated_by)
      values ('foresight', 1000, ${await approval('engagement.policy.set')}, ${'user:' + ALICE})
    `
    const transferApproval = await approval('engagement.transfer')
    await scratch`
      insert into engagement_transfers (service, amount_shards, approval_id)
      values ('foresight', 25, ${transferApproval})
    `

    await migrate(scratch as unknown as DbSql, MIGRATIONS, { service: 'admin-api-mig13-replay' })

    const WEI_PER_SHARD = 40_000_000_000_000_000n
    const policy = await scratch<{ transfer_cap_wei: string }[]>`
      select transfer_cap_wei from engagement_policies where service = 'foresight'
    `
    assert.equal(BigInt(policy[0]!.transfer_cap_wei), 1_000n * WEI_PER_SHARD, '40 EMBER, not 1000 wei')
    const transfer = await scratch<{ amount_wei: string }[]>`select amount_wei from engagement_transfers`
    assert.equal(BigInt(transfer[0]!.amount_wei), 25n * WEI_PER_SHARD, '1 EMBER, not 25 wei')

    // The cap trigger runs on the new column names, and the converted cap still bounds the
    // converted amount — a conversion that scaled one and not the other would pass here in one
    // direction and fail catastrophically in the other.
    await assert.rejects(
      async () => scratch`
        insert into engagement_transfers (service, amount_wei, approval_id)
        values ('foresight', ${(1_001n * WEI_PER_SHARD).toString()}, ${await approval('engagement.transfer')})
      `,
      /exceeds the policy cap/,
    )
    await scratch`
      insert into engagement_transfers (service, amount_wei, approval_id)
      values ('foresight', ${(1_000n * WEI_PER_SHARD).toString()}, ${await approval('engagement.transfer')})
    `

    // And so does the raise/lower asymmetry (21 §7.7), which is the trigger the conversion itself
    // had to be run around.
    await assert.rejects(
      () => scratch`update engagement_policies set transfer_cap_wei = transfer_cap_wei * 2 where service = 'foresight'`,
      /raising an engagement cap requires a fresh approved/,
    )
    await scratch`update engagement_policies set transfer_cap_wei = 1 where service = 'foresight'`
    await scratch`
      update engagement_policies
         set transfer_cap_wei = ${(2_000n * WEI_PER_SHARD).toString()},
             last_change_approval_id = ${await approval('engagement.policy.set')}
       where service = 'foresight'
    `
  } finally {
    await scratch.end({ timeout: 5 })
    await sql!.unsafe(`drop schema if exists ${SCHEMA} cascade`)
  }
})
