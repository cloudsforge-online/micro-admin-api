/**
 * The executors, driven directly — the file three other files already said existed.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THIS FILE IS NEW AND WHY THAT IS ITSELF A FINDING — micro-org#317.**
 *
 * `actions.ts` cited `actions.test.ts` twice ("`actions.test.ts` pins the exact body sent",
 * "`actions.test.ts` asserts it is passed") and `testsupport.ts` cited it once. There was no
 * `actions.test.ts`. The assertions were real — they were in `server.test.ts`, reached through the
 * HTTP route — so nothing was untested and every citation was a dead end.
 *
 * That is the same defect class as #317's headline: a comment that describes the repository rather
 * than the code, with nothing able to check it. It is written up rather than quietly repaired
 * because the two together say something the individual cases do not — the citations in this
 * service that go stale are the ones pointing OUTWARD, at the estate or at another file, and they
 * go stale silently every time. `routeidempotency.test.ts` already checks the SHAPE of the route
 * citations in `ACTIONS` for exactly this reason.
 *
 * **AND THESE ARE NOT COPIES OF THE ROUTE TESTS.** `server.test.ts` proves the executors are
 * reachable through two operators, an approval row and an audit chain; it needs Postgres and it
 * skips without it. These drive `EXECUTORS[...]` directly, need no database, and therefore RUN in
 * every environment including one with no Postgres at all — which matters for the one property
 * that is purely about the body sent upstream. The overlap is deliberate and is the cheap half.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ACTIONS,
  BASE_PLATFORM_ROLE,
  EXECUTORS,
  EXECUTABLE_ACTIONS,
  REVOCABLE_ROLES,
  type ExecutionContext,
} from './actions.ts'
import type { Approval } from './approvals.ts'
import type { Db } from './engagement.ts'
import {
  ALICE,
  CAROL,
  OPERATOR_ONE,
  OPERATOR_TWO,
  fakeBilling,
  fakeIdentity,
  fakeLedger,
  fakeMarket,
  type FakeIdentity,
} from './testsupport.ts'

const APPROVAL_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

function approval(overrides: Partial<Approval> = {}): Approval {
  return {
    id: APPROVAL_ID,
    action: 'identity.role.grant',
    subjectKind: 'user',
    subjectId: CAROL,
    params: { role: 'admin' },
    reasonCode: 'security_response',
    reason: 'promoting a second operator after the access review',
    // ALICE asked, BOB signed. Both appear below, and which one reaches identity is the point of
    // one of these cases.
    requestedBy: OPERATOR_ONE,
    requestedAt: '2026-08-10T09:00:00.000Z',
    expiresAt: '2026-08-10T13:00:00.000Z',
    state: 'approved',
    decidedBy: OPERATOR_TWO,
    decidedAt: '2026-08-10T09:05:00.000Z',
    decisionNote: null,
    executedAt: null,
    executionOutcome: null,
    executionDetail: null,
    correlationId: 'req-317',
    ...overrides,
  }
}

function context(identity: FakeIdentity, overrides: Partial<Approval> = {}): ExecutionContext {
  return {
    approval: approval(overrides),
    operatorBearer: 'the-approvers-own-bearer',
    // The APPROVER. Every executor records this as the actor, and it is not the requester.
    operator: OPERATOR_TWO,
    correlationId: 'req-317',
    ledger: fakeLedger(),
    market: fakeMarket(),
    billing: fakeBilling(),
    identity,
    // No executor exercised in this file touches the database. Cast rather than opened, so these
    // cases run with no Postgres anywhere — see the header.
    sql: null as unknown as Db,
  }
}

/* ------------------------------------------------------- the catalogue and its executors */

test('every executable action has an executor, and every executor an action', () => {
  // Both directions. A catalogue entry with no executor is a 501 an operator meets after two
  // signatures; an executor with no entry is code nothing can reach, which is worse because it
  // reads as a capability the service has.
  for (const name of EXECUTABLE_ACTIONS) {
    assert.ok(EXECUTORS[name], `${name} is executable and has no executor`)
  }
  for (const name of Object.keys(EXECUTORS)) {
    assert.ok(ACTIONS[name], `${name} executes something the catalogue does not list`)
  }
})

/* ------------------------------------------------------------------ the grant */

test('THE GRANT SENDS THE UNION, NOT THE BARE ROLE — the citation this file was written for', async () => {
  // The silent failure: identity's route REPLACES the role set (identity/src/platformRoles.ts),
  // and every registered user holds `player`, so `roles: ['admin']` would be a privilege REMOVAL
  // performed by an action named "grant". This is the assertion `actions.ts` has claimed lived
  // here since the executor was written.
  const identity = fakeIdentity()
  const result = await EXECUTORS['identity.role.grant']!(context(identity))

  assert.equal(identity.grants.length, 1)
  const sent = identity.grants[0]!
  assert.deepEqual([...sent.roles].sort(), ['admin', 'player'])
  assert.ok(sent.roles.includes(BASE_PLATFORM_ROLE), '`player` must survive the promotion')
  assert.deepEqual(result['granted'], ['admin'])
  assert.deepEqual(result['revoked'], [])
})

test('THE GRANT CARRIES THE APPROVAL ID, and names the APPROVER as actor', async () => {
  // Identity pairs `source='approval'` to `approval_id` with a CHECK written as an equality, so a
  // grant sent without one is refused by identity's database — at execution time, which is the
  // worst moment to discover it. And the actor is the person who SIGNED, not the person who asked:
  // they are different questions and identity's grant trail answers the first.
  const identity = fakeIdentity()
  await EXECUTORS['identity.role.grant']!(context(identity))

  const sent = identity.grants[0]!
  assert.equal(sent.approvalId, APPROVAL_ID)
  assert.equal(sent.actor, OPERATOR_TWO)
  assert.notEqual(sent.actor, OPERATOR_ONE)
  // The reason travels as code-and-text together: a dashboard groups by the first, a human reads
  // the second, and neither substitutes for the other.
  assert.match(sent.reason, /^security_response: /)
})

test('the grant sends the subject of the approval, never the operator', async () => {
  // The act-as-anyone check, at the executor rather than at the route. `subjectId` is the person
  // being promoted; `operator` is the person doing the promoting, and an executor that confused
  // them would promote whoever pressed the button.
  const identity = fakeIdentity()
  await EXECUTORS['identity.role.grant']!(context(identity, { subjectId: ALICE }))
  assert.equal(identity.grants[0]?.userId, ALICE)
})

test('a grant with no role parameter fails rather than sending an empty set', async () => {
  // `roles: ['player']` computed from a missing parameter is a silent demotion. It must throw.
  const identity = fakeIdentity()
  await assert.rejects(
    async () => EXECUTORS['identity.role.grant']!(context(identity, { params: {} })),
    /params\.role must be a non-empty string/,
  )
  assert.equal(identity.grants.length, 0)
})

/* ------------------------------------------------------------------ the revoke */

test('THE REVOKE REMOVES THE ROLE AND LEAVES THE BASE ROLE STANDING', async () => {
  const identity = fakeIdentity()
  // The subject holds both — which is the only state in which a revoke has anything to do, and the
  // state the fake cannot produce by default. Without this the case would pass on an executor that
  // removed nothing at all.
  identity.setPreviousRoles(['player', 'admin'])

  const result = await EXECUTORS['identity.role.revoke']!(
    context(identity, { action: 'identity.role.revoke' }),
  )

  assert.equal(identity.grants.length, 1)
  assert.deepEqual([...identity.grants[0]!.roles], [BASE_PLATFORM_ROLE])
  assert.deepEqual(result['revoked'], ['admin'], 'the role must actually come off')
  assert.deepEqual(result['granted'], [], 'a revoke must not grant anything')
  assert.deepEqual(result['roles'], ['player'])
  assert.equal(result['alreadyAbsent'], false)
})

test('the revoke carries the approval id and the approver, exactly as the grant does', async () => {
  // The de-escalation path must be no less attributable than the escalation path. That was the
  // whole complaint in #317: the only previous way to remove a role was a hand-run UPDATE, which
  // appears in no grant trail, no event and no audit chain.
  const identity = fakeIdentity()
  identity.setPreviousRoles(['player', 'admin'])
  await EXECUTORS['identity.role.revoke']!(context(identity, { action: 'identity.role.revoke' }))

  const sent = identity.grants[0]!
  assert.equal(sent.approvalId, APPROVAL_ID)
  assert.equal(sent.actor, OPERATOR_TWO)
  assert.equal(sent.userId, CAROL)
})

test('REVOKING A ROLE THE SUBJECT DOES NOT HOLD IS A TRUTHFUL NO-OP, not an error', async () => {
  // Identity computes `revoked` by diffing, so this is a 200 with an empty list. Throwing would
  // leave the approval `approved` and un-executed for ever — a queue full of approvals that can
  // never complete is worse than a recorded no-op — so the executor reports it instead.
  const identity = fakeIdentity()
  identity.setPreviousRoles(['player'])
  const result = await EXECUTORS['identity.role.revoke']!(
    context(identity, { action: 'identity.role.revoke' }),
  )
  assert.deepEqual(result['revoked'], [])
  assert.equal(result['alreadyAbsent'], true, 'the audit row must say the role was never held')
})

test('THE REVOCABLE LIST IS CLOSED, and the executor refuses to go outside it', async () => {
  // The interlock. Identity's write is a replacement and this executor cannot read what the
  // subject holds, so `[BASE_PLATFORM_ROLE]` is "revoke admin" only while `admin` is the sole
  // other role. A role outside the list must fail LOUDLY here rather than becoming a
  // set-replacement nobody reviewed — including `player` itself, whose removal would be a
  // deactivation this service has deliberately never had.
  assert.deepEqual([...REVOCABLE_ROLES], ['admin'])
  assert.ok(!REVOCABLE_ROLES.includes(BASE_PLATFORM_ROLE))

  for (const role of ['player', 'moderator', 'support']) {
    const identity = fakeIdentity()
    await assert.rejects(
      async () =>
        EXECUTORS['identity.role.revoke']!(
          context(identity, { action: 'identity.role.revoke', params: { role } }),
        ),
      /params\.role must be one of admin/,
      `revoking "${role}" must be refused`,
    )
    assert.equal(identity.grants.length, 0, 'identity must not be called at all')
  }
})

test('the two identity actions are the only ones whose subject is a person', () => {
  // Load-bearing since #317: `approvals_decider_is_not_the_subject` and `principalForSubject` are
  // both scoped to `subject_kind = 'user'`, so an action that started naming a person without
  // appearing here would sit outside the beneficiary check with nothing to say so.
  const userSubjects = Object.entries(ACTIONS)
    .filter(([, spec]) => spec.subjectKind === 'user')
    .map(([name]) => name)
    .sort()
  assert.deepEqual(userSubjects, ['identity.role.grant', 'identity.role.revoke'])
  // Both cost two operators. A de-escalation that were cheaper to authorise than an escalation
  // would be a one-operator route to removing every OTHER administrator.
  for (const name of userSubjects) assert.equal(ACTIONS[name]!.approval, 'two-operator')
})
