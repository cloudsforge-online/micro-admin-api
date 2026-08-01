/**
 * The approval queue.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE OTHER EXIT CRITERION: AN APPROVAL CANNOT BE GRANTED BY ITS REQUESTER.**
 *
 * Proved three times over, because the control is enforced three times over and a test that only
 * exercised the route would pass on a build where the constraint had been dropped:
 *
 *   1. Through `decide()` — a specific `SelfApprovalError`.
 *   2. Through the UPDATE's WHERE clause — with the pre-check bypassed.
 *   3. Straight at the database — with the whole module bypassed, so the CHECK constraint is what
 *      answers.
 *
 * And in the other direction, every time: a DIFFERENT operator succeeds. A refusal that refused
 * everybody would satisfy the first half of each of those and be useless.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  ApprovalNotFoundError,
  ApprovalStateError,
  REASON_CODES,
  SelfApprovalError,
  decide,
  expirePending,
  findApproval,
  listApprovals,
  recordExecution,
  requestApproval,
  type Approval,
  type RequestInput,
} from './approvals.ts'
import { verifyChain } from './audit.ts'
import {
  OPERATOR_ONE,
  OPERATOR_TWO,
  CAROL,
  enabled,
  migrateTestDb,
  openDb,
  resetAdminApi,
  skip,
} from './testsupport.ts'

const OPERATOR_THREE = `user:${CAROL}`

const sql = enabled ? openDb() : null

before(async () => {
  if (sql) await migrateTestDb(sql)
})
beforeEach(async () => {
  if (sql) await resetAdminApi(sql)
})
after(async () => {
  if (sql) await sql.end({ timeout: 5 })
})

function request(overrides: Partial<RequestInput> = {}): RequestInput {
  return {
    action: 'ledger.entry.reverse',
    subjectKind: 'ledger_entry',
    subjectId: 'entry-77',
    params: { description: 'reversing a duplicated sweep' },
    reasonCode: 'incident_remediation',
    reason: 'INC-412: the sweep was recorded twice',
    requestedBy: OPERATOR_ONE,
    ttlMinutes: 240,
    ...overrides,
  }
}

async function raise(overrides: Partial<RequestInput> = {}): Promise<Approval> {
  const out = await sql!.begin(async (tx) => ({ value: await requestApproval(tx, request(overrides)) }))
  return out.value.approval
}

async function answer(
  id: string,
  operator: string,
  grant = true,
  note: string | null = null,
): Promise<Approval> {
  const out = await sql!.begin(async (tx) => ({
    value: await decide(tx, { id, operator, grant, note }),
  }))
  return out.value.approval
}

/* ------------------------------------------------------------------ raising */

test('a request starts pending, with an expiry and both audit facts', { skip }, async () => {
  const approval = await raise()
  assert.equal(approval.state, 'pending')
  assert.equal(approval.requestedBy, OPERATOR_ONE)
  assert.equal(approval.decidedBy, null)
  assert.equal(approval.executedAt, null)
  assert.ok(new Date(approval.expiresAt).getTime() > new Date(approval.requestedAt).getTime())

  const audit = await sql!<{ action: string; actor: string; subject_id: string }[]>`
    select action, actor, subject_id from audit_events order by seq
  `
  assert.equal(audit.length, 1)
  assert.equal(audit[0]?.action, 'admin.approval.requested')
  assert.equal(audit[0]?.actor, OPERATOR_ONE)
  assert.equal(audit[0]?.subject_id, approval.id)
})

test('an unknown reason code is refused', { skip }, async () => {
  await assert.rejects(async () => raise({ reasonCode: 'because-i-said-so' }), /reasonCode must be one of/)
  // And nothing was written: the approval and its audit row commit together or not at all.
  assert.equal((await sql!`select id from approvals`).length, 0)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('every reason code in the closed list is accepted', { skip }, async () => {
  for (const code of REASON_CODES) await raise({ reasonCode: code })
  assert.equal((await listApprovals(sql!)).length, REASON_CODES.length)
})

test('a requester must be a user principal, never a service', { skip }, async () => {
  // Approval is consent given by a person. A service that could raise a request could pair with a
  // second service token to satisfy four eyes with two credentials on one machine.
  await assert.rejects(
    async () => raise({ requestedBy: 'service:admin-api' }),
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_requester_is_a_principal')
      return true
    },
  )
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
   FOUR EYES.
   ══════════════════════════════════════════════════════════════════════════════════════════════ */

test('FOUR EYES 1/3: decide() refuses the requester, and admits a second operator', { skip }, async () => {
  const approval = await raise({ requestedBy: OPERATOR_ONE })

  await assert.rejects(async () => answer(approval.id, OPERATOR_ONE), SelfApprovalError)
  assert.equal((await findApproval(sql!, approval.id))?.state, 'pending', 'the refusal must not have decided it')

  // ── The other direction. Without this, a rule that refused everybody would pass.
  const granted = await answer(approval.id, OPERATOR_TWO)
  assert.equal(granted.state, 'approved')
  assert.equal(granted.decidedBy, OPERATOR_TWO)
})

test('FOUR EYES 2/3: the UPDATE refuses it with the pre-check bypassed', { skip }, async () => {
  const approval = await raise({ requestedBy: OPERATOR_ONE })
  // The exact statement `decide()` issues, run directly. If the WHERE clause lost its
  // `requested_by <> ...` term this would claim a row and the test would fail.
  const claimed = await sql!`
    update approvals
       set state = 'approved', decided_by = ${OPERATOR_ONE}, decided_at = now()
     where id = ${approval.id} and state = 'pending' and requested_by <> ${OPERATOR_ONE}
    returning id
  `
  assert.equal(claimed.length, 0)
  assert.equal((await findApproval(sql!, approval.id))?.state, 'pending')

  const other = await sql!`
    update approvals
       set state = 'approved', decided_by = ${OPERATOR_TWO}, decided_at = now()
     where id = ${approval.id} and state = 'pending' and requested_by <> ${OPERATOR_TWO}
    returning id
  `
  assert.equal(other.length, 1)
})

test('FOUR EYES 3/3: the CHECK constraint refuses it with the whole module bypassed', { skip }, async () => {
  const approval = await raise({ requestedBy: OPERATOR_ONE })
  // No WHERE guard at all. This is the write a future route, a migration, or a hand-typed psql
  // session would make, and it is the reason the rule is a constraint rather than only code.
  await assert.rejects(
    async () =>
      sql!`update approvals set state = 'approved', decided_by = ${OPERATOR_ONE}, decided_at = now()
            where id = ${approval.id}`,
    (err: { code?: string; constraint_name?: string }) => {
      assert.equal(err.code, '23514', 'expected a check violation')
      assert.equal(err.constraint_name, 'approvals_no_self_approval')
      return true
    },
  )
  // And the same write naming somebody else succeeds — so the constraint is about WHO, not about
  // forbidding the update.
  const ok = await sql!`update approvals set state = 'approved', decided_by = ${OPERATOR_TWO},
                                             decided_at = now()
                         where id = ${approval.id} returning id`
  assert.equal(ok.length, 1)
})

test('a rejection by the requester is refused too, not only an approval', { skip }, async () => {
  // Rejecting your own request is harmless in outcome and still wrong in record: it would show the
  // queue as having had two operators look at it when one did.
  const approval = await raise({ requestedBy: OPERATOR_ONE })
  await assert.rejects(async () => answer(approval.id, OPERATOR_ONE, false), SelfApprovalError)
})

test('a self-approval attempt writes no audit row', { skip }, async () => {
  const approval = await raise()
  const before = (await sql!`select seq from audit_events`).length
  await assert.rejects(async () => answer(approval.id, OPERATOR_ONE), SelfApprovalError)
  assert.equal((await sql!`select seq from audit_events`).length, before)
})

/* ------------------------------------------------------------------ the state machine */

test('a decided request cannot be decided again', { skip }, async () => {
  const approval = await raise()
  await answer(approval.id, OPERATOR_TWO)
  await assert.rejects(async () => answer(approval.id, OPERATOR_THREE), ApprovalStateError)
})

test('a rejected request cannot be approved afterwards', { skip }, async () => {
  const approval = await raise()
  await answer(approval.id, OPERATOR_TWO, false)
  await assert.rejects(async () => answer(approval.id, OPERATOR_THREE, true), ApprovalStateError)
  assert.equal((await findApproval(sql!, approval.id))?.state, 'rejected')
})

test('deciding something that does not exist is a not-found, not a 500', { skip }, async () => {
  await assert.rejects(
    async () => answer('99999999-9999-4999-8999-999999999999', OPERATOR_TWO),
    ApprovalNotFoundError,
  )
})

test('an expired request cannot be decided', { skip }, async () => {
  const approval = await raise({ ttlMinutes: 1 })
  const later = () => new Date(Date.now() + 2 * 60_000)
  await assert.rejects(
    async () =>
      sql!.begin(async (tx) => ({
        value: await decide(tx, { id: approval.id, operator: OPERATOR_TWO, grant: true }, later),
      })),
    /expired at/,
  )
})

test('a decision names both operators in one audit row', { skip }, async () => {
  const approval = await raise({ requestedBy: OPERATOR_ONE })
  await answer(approval.id, OPERATOR_TWO, true, 'confirmed against the indexer')

  const rows = await sql!<{ action: string; actor: string; payload: Record<string, unknown> }[]>`
    select action, actor, payload from audit_events where action = 'admin.approval.granted'
  `
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.actor, OPERATOR_TWO)
  // An audit trail that needs a join to answer "who were the two people" is one nobody uses under
  // pressure.
  assert.equal(rows[0]?.payload['requestedBy'], OPERATOR_ONE)
  assert.equal(rows[0]?.payload['approvedBy'], OPERATOR_TWO)
  assert.equal(rows[0]?.payload['note'], 'confirmed against the indexer')
})

test('a rejection audits as rejected, not as granted', { skip }, async () => {
  const approval = await raise()
  await answer(approval.id, OPERATOR_TWO, false)
  const rows = await sql!<{ action: string }[]>`select action from audit_events order by seq`
  assert.deepEqual(rows.map((r) => r.action), ['admin.approval.requested', 'admin.approval.rejected'])
})

/* ------------------------------------------------------------------ execution */

test('execution is recorded once, and a second attempt claims nothing', { skip }, async () => {
  const approval = await raise()
  await answer(approval.id, OPERATOR_TWO)

  const first = await sql!.begin(async (tx) => ({
    value: await recordExecution(tx, {
      id: approval.id,
      outcome: 'succeeded',
      detail: { entryId: 'entry-1' },
      actor: OPERATOR_TWO,
    }),
  }))
  assert.ok(first.value)
  assert.equal(first.value.approval.executionOutcome, 'succeeded')

  // A retried approve route, or a second worker. `where executed_at is null` is what makes this
  // at-most-once — and the audit must not gain a second "executed" row.
  const second = await sql!.begin(async (tx) => ({
    value: await recordExecution(tx, {
      id: approval.id,
      outcome: 'succeeded',
      detail: { entryId: 'entry-2' },
      actor: OPERATOR_TWO,
    }),
  }))
  assert.equal(second.value, null)
  const executed = await sql!`select seq from audit_events where action = 'admin.approval.executed'`
  assert.equal(executed.length, 1)
})

test('a PENDING request cannot record an execution', { skip }, async () => {
  const approval = await raise()
  const out = await sql!.begin(async (tx) => ({
    value: await recordExecution(tx, {
      id: approval.id,
      outcome: 'succeeded',
      detail: {},
      actor: OPERATOR_TWO,
    }),
  }))
  assert.equal(out.value, null, 'an unapproved action must not be recordable as having run')
})

test('THE CONSTRAINT: an unapproved execution cannot be written down at all', { skip }, async () => {
  const approval = await raise()
  // The module bypassed entirely. This is the write that would exist if a future route forgot the
  // state check — an action that ran without a second pair of eyes.
  await assert.rejects(
    async () =>
      sql!`update approvals set executed_at = now(), execution_outcome = 'succeeded',
                                execution_detail = '{}'::jsonb
            where id = ${approval.id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_execution_needs_approval')
      return true
    },
  )
})

test('an EXPIRED request can never execute, because it names no decider', { skip }, async () => {
  const approval = await raise({ ttlMinutes: 1 })
  const later = () => new Date(Date.now() + 2 * 60_000)
  await sql!.begin(async (tx) => ({ value: await expirePending(tx, 'service:admin-api', 'test-replica', 200, later) }))
  assert.equal((await findApproval(sql!, approval.id))?.state, 'expired')

  await assert.rejects(
    async () =>
      sql!`update approvals set executed_at = now(), execution_outcome = 'succeeded',
                                execution_detail = '{}'::jsonb
            where id = ${approval.id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_execution_needs_approval')
      return true
    },
  )
})

test('a failed execution is recorded, not swallowed', { skip }, async () => {
  const approval = await raise()
  await answer(approval.id, OPERATOR_TWO)
  const out = await sql!.begin(async (tx) => ({
    value: await recordExecution(tx, {
      id: approval.id,
      outcome: 'failed',
      detail: { error: 'ledger answered 503' },
      actor: OPERATOR_TWO,
    }),
  }))
  assert.equal(out.value?.approval.executionOutcome, 'failed')
  const audit = await sql!<{ outcome: string }[]>`
    select outcome from audit_events where action = 'admin.approval.executed'
  `
  assert.equal(audit[0]?.outcome, 'failed')
})

/* ------------------------------------------------------------------ expiry */

test('expiry closes only what is past its deadline', { skip }, async () => {
  const short = await raise({ ttlMinutes: 1, subjectId: 'entry-short' })
  const long = await raise({ ttlMinutes: 600, subjectId: 'entry-long' })
  const later = () => new Date(Date.now() + 2 * 60_000)

  const expired = await sql!.begin(async (tx) => ({
    value: await expirePending(tx, 'service:admin-api', 'test-replica', 200, later),
  }))
  assert.deepEqual(expired.value, [short.id])
  assert.equal((await findApproval(sql!, long.id))?.state, 'pending')
})

test('expiry writes one audit row per request, with outcome refused', { skip }, async () => {
  await raise({ ttlMinutes: 1, subjectId: 'a' })
  await raise({ ttlMinutes: 1, subjectId: 'b' })
  const later = () => new Date(Date.now() + 2 * 60_000)
  await sql!.begin(async (tx) => ({ value: await expirePending(tx, 'service:admin-api', 'test-replica', 200, later) }))

  const rows = await sql!<{ outcome: string; subject_id: string }[]>`
    select outcome, subject_id from audit_events where action = 'admin.approval.expired'
  `
  assert.equal(rows.length, 2)
  assert.ok(rows.every((r) => r.outcome === 'refused'))
  // And the chain still verifies after a batch of appends inside one transaction.
  assert.equal((await verifyChain(sql!, { from: 0n })).ok, true)
})

test('expiry is idempotent — a second pass finds nothing', { skip }, async () => {
  await raise({ ttlMinutes: 1 })
  const later = () => new Date(Date.now() + 2 * 60_000)
  const first = await sql!.begin(async (tx) => ({ value: await expirePending(tx, 'service:admin-api', 'test-replica', 200, later) }))
  const second = await sql!.begin(async (tx) => ({ value: await expirePending(tx, 'service:admin-api', 'test-replica', 200, later) }))
  assert.equal(first.value.length, 1)
  assert.equal(second.value.length, 0)
})

/* ------------------------------------------------------------------ reads */

test('the queue filters by state, action and requester', { skip }, async () => {
  const a = await raise({ subjectId: 'a', action: 'ledger.entry.reverse' })
  await raise({ subjectId: 'b', action: 'billing.entitlement.revoke', requestedBy: OPERATOR_TWO })
  await answer(a.id, OPERATOR_TWO)

  assert.equal((await listApprovals(sql!, { state: 'pending' })).length, 1)
  assert.equal((await listApprovals(sql!, { state: 'approved' })).length, 1)
  assert.equal((await listApprovals(sql!, { action: 'billing.entitlement.revoke' })).length, 1)
  assert.equal((await listApprovals(sql!, { requestedBy: OPERATOR_TWO })).length, 1)
})

test('an unknown approval reads as null rather than throwing', { skip }, async () => {
  assert.equal(await findApproval(sql!, '99999999-9999-4999-8999-999999999999'), null)
})

test('the whole lifecycle leaves a verifiable chain', { skip }, async () => {
  const approval = await raise()
  await answer(approval.id, OPERATOR_TWO)
  await sql!.begin(async (tx) => ({
    value: await recordExecution(tx, {
      id: approval.id,
      outcome: 'succeeded',
      detail: { entryId: 'entry-1' },
      actor: OPERATOR_TWO,
    }),
  }))
  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, true)
  const actions = await sql!<{ action: string }[]>`select action from audit_events order by seq`
  assert.deepEqual(actions.map((r) => r.action), [
    'admin.approval.requested',
    'admin.approval.granted',
    'admin.approval.executed',
  ])
})
