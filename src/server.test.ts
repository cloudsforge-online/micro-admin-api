/**
 * The HTTP surface, over a real socket against a real database.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE THREE PROPERTIES THIS FILE EXISTS TO PIN.**
 *
 *   1. **An operator acts as themselves.** No route accepts an `actor` from the caller, and the
 *      recorded actor is always the token's subject. Asserted by sending an `actor` in the body
 *      and proving it was ignored.
 *   2. **A service token cannot act.** It can read and it can mirror; it cannot request, approve
 *      or execute. Asserted per route.
 *   3. **The operator's own bearer reaches the upstreams that can record it.** SD-11 calls that
 *      the one genuinely good decision in nimbus's admin proxies, and the fakes capture the exact
 *      bearer so the test can assert WHICH operator's token arrived.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
/**
 * `SIGNATURE_HEADER` is imported from **`contracts-events`**, not from `./outbox.ts`.
 *
 * That is deliberate and it is load-bearing. This suite used to take the constant from the module
 * under test, so the test and the route always agreed on the header name no matter what that name
 * was — and they agreed on `x-cloudsforge-signature`, which nothing in the estate sends. A test
 * that reads its expectations out of the implementation cannot discover that the implementation is
 * talking to nobody. Here the header, the signing function and the tolerance all come from the
 * package that owns the wire format, so this suite speaks the protocol rather than the code.
 */
import { DELIVERY_TOLERANCE_MS, SIGNATURE_HEADER, signDelivery } from '@cloudsforge/contracts-events'
import { READ_SCOPE } from './scopes.ts'
import { readAudit, verifyChain, type AuditRow } from './audit.ts'
import {
  ALICE,
  BOB,
  CAROL,
  OPERATOR_ONE,
  OPERATOR_TWO,
  enabled,
  fakeReadiness,
  fakeVerifier,
  freshKey,
  migrateTestDb,
  openDb,
  operatorPrincipal,
  playerPrincipal,
  refused,
  resetAdminApi,
  servicePrincipal,
  skip,
  startHarness,
  unreachable,
  type FakeVerifier,
  type Harness,
} from './testsupport.ts'

const SIGNING_SECRET = 'a-test-signing-secret-of-sufficient-length'

/** The secret a rotation moves TO. Obviously fake, and long enough to pass the 24-character rule. */
const ROTATED_SECRET = 'a-test-rotated-secret-of-sufficient-length'

/** Opaque bearers. The token IS the identity here, so a forwarded one is checkable. */
const ONE = 'operator-one-bearer'
const TWO = 'operator-two-bearer'
const THREE = 'operator-three-bearer'
const PLAYER = 'ordinary-player-bearer'
const READER = 'reader-service-bearer'
const NOSCOPE = 'unscoped-service-bearer'

const sql = enabled ? openDb() : null
let harness: Harness | null = null
let verifier: FakeVerifier | null = null

before(async () => {
  if (!sql) return
  await migrateTestDb(sql)
  verifier = fakeVerifier({
    [ONE]: operatorPrincipal(ALICE),
    [TWO]: operatorPrincipal(BOB),
    [THREE]: operatorPrincipal(CAROL),
    [PLAYER]: playerPrincipal(ALICE),
    [READER]: servicePrincipal('lantern', [READ_SCOPE]),
    [NOSCOPE]: servicePrincipal('site', []),
  })
  harness = await startHarness(sql, verifier, {
    acceptSecrets: [SIGNING_SECRET],
    readiness: fakeReadiness({
      identity: { ready: true, state: 'ready' },
      ledger: { ready: true, state: 'ready' },
    }),
  })
})
beforeEach(async () => {
  if (sql) await resetAdminApi(sql)
  harness?.reset()
  harness?.verifier.unavailable(false)
})
after(async () => {
  await harness?.close()
  if (sql) await sql.end({ timeout: 5 })
})

const h = (): Harness => harness!

async function raise(
  token: string,
  overrides: Record<string, unknown> = {},
): Promise<{ status: number; body: any }> {
  return h().request('POST', '/v1/approvals', {
    token,
    headers: { 'idempotency-key': freshKey() },
    body: {
      action: 'ledger.entry.reverse',
      subjectId: 'entry-77',
      params: { description: 'reversing a duplicated sweep' },
      reasonCode: 'incident_remediation',
      reason: 'INC-412: the sweep was recorded twice',
      ...overrides,
    },
  })
}

async function answer(token: string, id: string, grant = true): Promise<{ status: number; body: any }> {
  return h().request('POST', `/v1/approvals/${id}/decision`, {
    token,
    headers: { 'idempotency-key': freshKey() },
    body: { grant },
  })
}

/* ------------------------------------------------------------------ health */

test('/livez is static and needs no token', { skip }, async () => {
  const res = await h().request('GET', '/livez')
  assert.equal(res.status, 200)
  assert.equal(res.body.ok, true)
})

test('/readyz reports real state', { skip }, async () => {
  const res = await h().request('GET', '/readyz')
  assert.equal(res.status, 200)
  assert.equal(res.body.ready, true)
})

test('/metrics answers Prometheus text', { skip }, async () => {
  await raise(ONE)
  const res = await h().request('GET', '/metrics')
  assert.equal(res.status, 200)
  assert.match(res.headers['content-type'] ?? '', /text\/plain/)
  assert.match(res.text, /# HELP admin_operator_actions_total/)
})

test('an unmatched path is 404, with a request id', { skip }, async () => {
  const res = await h().request('GET', '/v1/nothing-here', { token: ONE })
  assert.equal(res.status, 404)
  assert.ok(res.headers['x-request-id'])
})

test('every response carries the request id it was given', { skip }, async () => {
  const res = await h().request('GET', '/livez', { headers: { 'x-request-id': 'quotable-id-01' } })
  assert.equal(res.headers['x-request-id'], 'quotable-id-01')
})

test('a hostile request id is replaced rather than echoed', { skip }, async () => {
  const res = await h().request('GET', '/livez', { headers: { 'x-request-id': 'a b\tc' } })
  assert.notEqual(res.headers['x-request-id'], 'a b\tc')
})

test('nothing on this surface is cacheable', { skip }, async () => {
  // An operator acting on a ninety-second-old "ledger: ok" is acting on a fact that has changed.
  const res = await h().request('GET', '/v1/approvals', { token: ONE })
  assert.equal(res.headers['cache-control'], 'no-store')
})

/* ------------------------------------------------------------------ authentication */

test('no token is 401, and the reason is not returned', { skip }, async () => {
  const res = await h().request('GET', '/v1/approvals')
  assert.equal(res.status, 401)
  assert.equal(res.body.error.code, 'unauthenticated')
  // "signature verification failed" versus "expired" tells an attacker which half to fix.
  assert.equal(res.body.error.message, 'a valid bearer token is required')
})

test('an unknown token is 401', { skip }, async () => {
  const res = await h().request('GET', '/v1/approvals', { token: 'forged' })
  assert.equal(res.status, 401)
})

test('an unreachable JWKS is 503, NEVER 401', { skip }, async () => {
  // Answering 401 would sign every operator out because identity is having a bad minute — and
  // this is the surface somebody is trying to use during that minute.
  h().verifier.unavailable(true)
  const res = await h().request('GET', '/v1/approvals', { token: ONE })
  assert.equal(res.status, 503)
  assert.equal(res.body.error.code, 'verifier_unavailable')
  h().verifier.unavailable(false)
})

test('an ordinary user without role:admin is 403 everywhere', { skip }, async () => {
  for (const [method, path] of [
    ['GET', '/v1/approvals'],
    ['GET', '/v1/audit'],
    ['GET', '/v1/flags'],
    ['GET', '/v1/estate'],
  ] as const) {
    const res = await h().request(method, path, { token: PLAYER })
    assert.equal(res.status, 403, `${method} ${path}`)
    assert.match(res.body.error.message, /role:admin/)
  }
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
   A SERVICE TOKEN CANNOT ACT.
   ══════════════════════════════════════════════════════════════════════════════════════════════ */

test('a service token may READ with the exact scope', { skip }, async () => {
  for (const path of ['/v1/approvals', '/v1/audit', '/v1/flags', '/v1/broadcasts', '/v1/actions']) {
    assert.equal((await h().request('GET', path, { token: READER })).status, 200, path)
  }
})

test('a service token without the exact scope is refused every read', { skip }, async () => {
  for (const path of ['/v1/approvals', '/v1/audit', '/v1/flags']) {
    assert.equal((await h().request('GET', path, { token: NOSCOPE })).status, 403, path)
  }
})

test('a service token CANNOT request, approve, flip a flag, broadcast or read the estate', { skip }, async () => {
  // Approval is consent given by a person. A service token that could approve would make four
  // eyes satisfiable by two credentials on one machine.
  const raised = await raise(READER)
  assert.equal(raised.status, 403)
  assert.match(raised.body.error.message, /a service token cannot act as an operator/)

  const approval = (await raise(ONE)).body.approval
  assert.equal((await answer(READER, approval.id)).status, 403)
  assert.equal(
    (
      await h().request('PUT', '/v1/flags/market.listing', {
        token: READER,
        body: { enabled: true, description: 'x', owner: 'platform' },
      })
    ).status,
    403,
  )
  assert.equal(
    (
      await h().request('POST', '/v1/broadcasts', {
        token: READER,
        headers: { 'idempotency-key': freshKey() },
        body: { severity: 'info', title: 't', body: 'b' },
      })
    ).status,
    403,
  )
  assert.equal((await h().request('GET', '/v1/estate', { token: READER })).status, 403)
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
   AN OPERATOR ACTS AS THEMSELVES.
   ══════════════════════════════════════════════════════════════════════════════════════════════ */

test('an `actor` in the body is ignored — the token decides', { skip }, async () => {
  const res = await raise(ONE, { actor: OPERATOR_TWO, requestedBy: OPERATOR_TWO, userId: BOB })
  assert.equal(res.status, 201)
  assert.equal(res.body.approval.requestedBy, OPERATOR_ONE)

  const audit = await sql!<{ actor: string }[]>`select actor from audit_events order by seq`
  assert.equal(audit[0]?.actor, OPERATOR_ONE, 'the audit must name the token holder, not the body')
})

test('a user is a SUBJECT, never a costume', { skip }, async () => {
  const res = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: {
      action: 'billing.entitlement.revoke',
      subjectId: 'entitlement-9',
      params: { reason: 'chargeback' },
      reasonCode: 'customer_dispute',
      reason: 'DIS-9: chargeback received',
    },
  })
  assert.equal(res.status, 201)
  // The REQUEST is about the approval; the entitlement is its target, in the payload. The
  // distinction is the point: `subject_kind: 'user'` on a request row would read as the operator
  // having done something to a user, when what they did was ask for permission.
  const audit = await sql!<{ actor: string; subject_kind: string; payload: any }[]>`
    select actor, subject_kind, payload from audit_events order by seq
  `
  assert.equal(audit[0]?.actor, OPERATOR_ONE)
  assert.equal(audit[0]?.subject_kind, 'approval')
  assert.equal(audit[0]?.payload.target.kind, 'entitlement')
  assert.equal(audit[0]?.payload.target.id, 'entitlement-9')
})

test('THERE IS NO ROUTE THAT TAKES A userId AND ACTS FOR IT', { skip }, async () => {
  // The frozen estate's /internal routes did, and deploy/gateway/dynamic/policy.yml refuses them
  // from outside for that reason. Asserted against the source, because the defect is an ABSENCE
  // and an absence has no behaviour to test.
  const { readFileSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const source = readFileSync(fileURLToPath(new URL('./server.ts', import.meta.url)), 'utf8')
  const routes = [...source.matchAll(/define\('[A-Z]+', '([^']+)'/g)].map((m) => m[1]!)
  assert.ok(routes.length >= 14, `expected many routes, found ${routes.length}`)
  for (const route of routes) {
    assert.ok(!/:userId|\/internal\//.test(route), `${route} looks like an act-as-anyone route`)
  }
  // And no handler reads a userId out of a query string or a body.
  assert.ok(!/searchParams\.get\('userId'\)/.test(source), 'a userId query parameter is an act-as-anyone primitive')
  assert.ok(!/body\['actor'\]|body\['requestedBy'\]/.test(source), 'the actor must come from the token')
})

/* ------------------------------------------------------------------ the approval route */

/**
 * **INTENTIONAL EXPECTATION CHANGE — this asserted a 501 and now asserts acceptance.**
 *
 * The 501 was the §3.3g refusal: identity had no route that assigns `users.roles`, so the queue
 * refused to accept work it could never execute. Identity has since built exactly the route this
 * repository specified, so refusing would now be the lie — an operator would be told the estate
 * cannot promote anyone when it can.
 *
 * The refusal machinery itself is NOT deleted: `ActionUnavailableError` and the `blockedReason`
 * pairing still exist and are still pinned by `bootstrap.test.ts` and `routeidempotency.test.ts`,
 * so the next action that lands without an upstream gets the same treatment.
 */
test('a role grant is now ACCEPTED into the queue, and still costs two operators', { skip }, async () => {
  const good = await raise(ONE)
  assert.equal(good.status, 201)
  assert.equal(good.body.approval.state, 'pending')

  const grant = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: {
      action: 'identity.role.grant',
      subjectId: ALICE,
      params: { role: 'admin' },
      reasonCode: 'security_response',
      reason: 'promoting a second operator after the bootstrap',
    },
  })
  assert.equal(grant.status, 201)
  // PENDING, not approved. Raising is not authorising, and the requester's own signature is not
  // one of the two — `approvals_no_self_approval` is what makes four eyes mean four eyes.
  assert.equal(grant.body.approval.state, 'pending')
  assert.equal((await sql!`select id from approvals`).length, 2)
})

test('THE ROLE GRANT REACHES IDENTITY WITH THE APPROVAL ID AND WITHOUT REVOKING `player`', { skip }, async () => {
  // The two silent failure modes of this executor, both asserted on the exact body sent:
  //
  //   1. `roles: ['admin']` would REVOKE `player`, because identity's route replaces the set
  //      rather than adding to it (identity/src/platformRoles.ts) and every registered
  //      user holds `player`. A privilege removal disguised as a grant.
  //   2. A missing `approvalId` would be refused by identity's CHECK — but only there, and only
  //      at execution time, which is the worst moment to find out.
  const raised = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: {
      action: 'identity.role.grant',
      subjectId: ALICE,
      params: { role: 'admin' },
      reasonCode: 'security_response',
      reason: 'promoting a second operator',
    },
  })
  assert.equal(raised.status, 201)
  const id = raised.body.approval.id

  // A DIFFERENT operator approves, and the decision executes. Two eyes are not four.
  const granted = await answer(TWO, id)
  assert.equal(granted.status, 201, JSON.stringify(granted.body))
  assert.equal(granted.body.approval.executionOutcome, 'succeeded')

  assert.equal(h().identity.grants.length, 1)
  const sent = h().identity.grants[0]!
  assert.equal(sent.userId, ALICE)
  assert.deepEqual([...sent.roles].sort(), ['admin', 'player'], '`player` must survive the promotion')
  assert.equal(sent.approvalId, id, 'identity pairs source=approval to this id with a CHECK')
  // The APPROVER is the recorded actor, not the requester — they are different questions and the
  // grant trail answers "who signed for this".
  assert.equal(sent.actor, OPERATOR_TWO)
  assert.match(sent.reason, /security_response/)
})

test('an unknown action is 400, not 501', { skip }, async () => {
  const res = await raise(ONE, { action: 'ledger.print.money' })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /action must be one of/)
})

test('a missing required parameter is 400 and names the parameter', { skip }, async () => {
  const res = await raise(ONE, { params: {} })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /params\.description is required/)
})

test('an unknown reason code is 400', { skip }, async () => {
  const res = await raise(ONE, { reasonCode: 'felt-like-it' })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /reasonCode must be one of/)
})

test('THE FOUR-EYES REFUSAL over HTTP: 403, with its own code', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  const self = await answer(ONE, approval.id)
  assert.equal(self.status, 403)
  assert.equal(self.body.error.code, 'self_approval_refused')

  // ── The other direction.
  const other = await answer(TWO, approval.id)
  assert.equal(other.status, 201)
  assert.equal(other.body.approval.state, 'approved')
  assert.equal(other.body.approval.decidedBy, OPERATOR_TWO)
})

test('a self-approval attempt is counted, so it can be alerted on', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  await answer(ONE, approval.id)
  assert.match(h().metrics.render(), /admin_self_approvals_refused_total \d+/)
})

test('a granted approval EXECUTES against the upstream, with the operator recorded', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  const granted = await answer(TWO, approval.id)

  assert.equal(granted.status, 201)
  assert.equal(granted.body.execution.entryId, 'entry-1')
  assert.equal(granted.body.approval.executionOutcome, 'succeeded')

  assert.equal(h().ledger.reversals.length, 1)
  const call = h().ledger.reversals[0]!
  assert.equal(call.entryId, 'entry-77')
  // The APPROVER is the operator on the record: they are the one authorising the run.
  assert.equal(call.operator, OPERATOR_TWO)
  assert.equal(call.approvalId, approval.id)
  // Derived from the approval id, so a retry replays rather than posting a second reversal.
  assert.equal(call.idempotencyKey, `admin-api:approval:${approval.id}`)
})

test('a rejected approval executes nothing', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  const rejected = await answer(TWO, approval.id, false)
  assert.equal(rejected.body.approval.state, 'rejected')
  assert.equal(rejected.body.execution, null)
  assert.equal(h().ledger.reversals.length, 0)
})

test('THE OPERATOR BEARER REACHES market, so market records the administrator', { skip }, async () => {
  const approval = (
    await h().request('POST', '/v1/approvals', {
      token: ONE,
      headers: { 'idempotency-key': freshKey() },
      body: {
        action: 'market.moderation.case.resolve',
        subjectId: 'case-3',
        params: { state: 'upheld' },
        reasonCode: 'fraud_response',
        reason: 'the listing is a scam',
      },
    })
  ).body.approval

  await answer(TWO, approval.id)
  assert.equal(h().market.resolved.length, 1)
  // SD-11: "Pay and custody record WHICH administrator acted." The bearer that arrived is the
  // approver's own, not this service's credential — which is what makes that true.
  assert.equal(h().market.resolved[0]?.bearer, TWO)
  assert.equal(h().market.resolved[0]?.state, 'upheld')
})

test('THE OPERATOR BEARER REACHES billing too', { skip }, async () => {
  const approval = (
    await h().request('POST', '/v1/approvals', {
      token: ONE,
      headers: { 'idempotency-key': freshKey() },
      body: {
        action: 'billing.entitlement.revoke',
        subjectId: 'entitlement-9',
        params: { reason: 'chargeback received', refund: true },
        reasonCode: 'customer_dispute',
        reason: 'DIS-9',
      },
    })
  ).body.approval

  await answer(THREE, approval.id)
  assert.equal(h().billing.revocations.length, 1)
  assert.equal(h().billing.revocations[0]?.bearer, THREE)
  assert.equal(h().billing.revocations[0]?.refund, true)
})

test('a failed execution is recorded on the row AND surfaced to the operator', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  h().ledger.failWith(refused('ledger', 409))

  const res = await answer(TWO, approval.id)
  assert.equal(res.status, 502, 'the peer decided — retrying produces the same answer')
  assert.equal(res.body.error.code, 'upstream_refused')

  // The approval stays APPROVED and unexecuted-successfully: two operators did agree, and erasing
  // that would need a third signature for something already authorised twice.
  const row = (await h().request('GET', `/v1/approvals/${approval.id}`, { token: ONE })).body.approval
  assert.equal(row.state, 'approved')
  assert.equal(row.executionOutcome, 'failed')
  assert.match(String(row.executionDetail.error), /ledger answered 409/)
})

test('an unreachable upstream is 503, not 502', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  h().ledger.failWith(unreachable('ledger'))
  const res = await answer(TWO, approval.id)
  assert.equal(res.status, 503)
  assert.equal(res.body.error.code, 'upstream_unavailable')
})

test('an upstream error body never reaches the operator console', { skip }, async () => {
  // An upstream's error body can carry a subject's email or a listing's private terms, and this
  // string is rendered in a console and logged with a wider audience than the upstream's own.
  const approval = (await raise(ONE)).body.approval
  h().ledger.failWith(refused('ledger', 400))
  const res = await answer(TWO, approval.id)
  assert.equal(res.body.error.message, 'ledger answered 400')
})

test('a decided approval cannot be decided again', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  await answer(TWO, approval.id)
  const again = await answer(THREE, approval.id)
  assert.equal(again.status, 409)
  assert.equal(again.body.error.code, 'state_conflict')
})

test('deciding a malformed id is 404, never 500', { skip }, async () => {
  const res = await answer(TWO, 'not-a-uuid')
  assert.equal(res.status, 404)
})

test('the queue and one request read back', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  const list = await h().request('GET', '/v1/approvals?state=pending', { token: TWO })
  assert.equal(list.body.approvals.length, 1)
  const one = await h().request('GET', `/v1/approvals/${approval.id}`, { token: TWO })
  assert.equal(one.body.approval.id, approval.id)
  const missing = await h().request('GET', '/v1/approvals/99999999-9999-4999-8999-999999999999', { token: TWO })
  assert.equal(missing.status, 404)
})

test('the action catalogue is served, and the role grant is no longer blocked', { skip }, async () => {
  // Intentional expectation change: this asserted `route === null` and a `blockedReason` naming a
  // route identity did not have. Identity now has it, so the console must render the action as
  // available rather than greying it out with a stale explanation.
  const res = await h().request('GET', '/v1/actions', { token: ONE })
  assert.equal(res.status, 200)
  const grant = res.body.actions.find((a: { name: string }) => a.name === 'identity.role.grant')
  assert.ok(grant, 'the role grant left the catalogue entirely')
  assert.equal(grant.blockedReason, null)
  assert.match(grant.route, /PUT \/internal\/users\/:id\/roles/)
  assert.ok(res.body.reasonCodes.includes('incident_remediation'))
})

/* ------------------------------------------------------------------ idempotency */

test('a mutating route without an Idempotency-Key is 400', { skip }, async () => {
  const res = await h().request('POST', '/v1/approvals', {
    token: ONE,
    body: { action: 'ledger.entry.reverse', subjectId: 'e', params: { description: 'd' }, reasonCode: 'data_correction', reason: 'r' },
  })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /requires an Idempotency-Key/)
})

test('AN IDEMPOTENT RETRY REPLAYS, and creates no second request', { skip }, async () => {
  const key = freshKey('replay')
  const body = {
    action: 'ledger.entry.reverse',
    subjectId: 'entry-77',
    params: { description: 'reversing a duplicated sweep' },
    reasonCode: 'incident_remediation',
    reason: 'INC-412',
  }
  const first = await h().request('POST', '/v1/approvals', { token: ONE, headers: { 'idempotency-key': key }, body })
  const second = await h().request('POST', '/v1/approvals', { token: ONE, headers: { 'idempotency-key': key }, body })

  assert.equal(first.status, 201)
  assert.equal(second.status, 200, 'a replay is a 200, not a fresh 201')
  assert.equal(second.body.approval.id, first.body.approval.id)
  assert.equal((await sql!`select id from approvals`).length, 1)
  // And exactly one audit row, so the chain does not show the request being raised twice.
  assert.equal((await sql!`select seq from audit_events`).length, 1)
})

test('a retry with a FRESH correlation id still replays', { skip }, async () => {
  // The ledger fingerprinted the whole body including the correlation id, so every honest retry
  // would have 409'd in production. Pinned here in both directions.
  const key = freshKey('correlated')
  const body = {
    action: 'ledger.entry.reverse',
    subjectId: 'entry-77',
    params: { description: 'd' },
    reasonCode: 'data_correction',
    reason: 'r',
  }
  const first = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': key, 'x-request-id': 'attempt-one' },
    body: { ...body, correlationId: 'attempt-one' },
  })
  const second = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': key, 'x-request-id': 'attempt-two' },
    body: { ...body, correlationId: 'attempt-two' },
  })
  assert.equal(second.status, 200)
  assert.equal(second.body.approval.id, first.body.approval.id)
})

test('the same key with a GENUINELY different body is 409, not a replay', { skip }, async () => {
  const key = freshKey('reused')
  await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': key },
    body: { action: 'ledger.entry.reverse', subjectId: 'entry-A', params: { description: 'd' }, reasonCode: 'data_correction', reason: 'r' },
  })
  const different = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': key },
    body: { action: 'ledger.entry.reverse', subjectId: 'entry-B', params: { description: 'd' }, reasonCode: 'data_correction', reason: 'r' },
  })
  assert.equal(different.status, 409)
  assert.equal(different.body.error.code, 'idempotency_key_reused')
})

test('two operators may reuse the same client key without colliding', { skip }, async () => {
  // Keys are chosen by callers, and two operators independently choosing `remediate-2026-08-01`
  // must not collide — here a collision would replay one operator's request as the answer to
  // another's, and the audit would show the wrong name.
  const key = 'remediate-2026-08-01'
  const body = {
    action: 'ledger.entry.reverse',
    subjectId: 'entry-77',
    params: { description: 'd' },
    reasonCode: 'data_correction',
    reason: 'r',
  }
  const first = await h().request('POST', '/v1/approvals', { token: ONE, headers: { 'idempotency-key': key }, body })
  const second = await h().request('POST', '/v1/approvals', { token: TWO, headers: { 'idempotency-key': key }, body })
  assert.equal(first.status, 201)
  assert.equal(second.status, 201)
  assert.notEqual(first.body.approval.id, second.body.approval.id)
  assert.equal(second.body.approval.requestedBy, OPERATOR_TWO)
})

test('a retried DECISION does not execute the action twice', { skip }, async () => {
  const approval = (await raise(ONE)).body.approval
  const key = freshKey('decide')
  const first = await h().request('POST', `/v1/approvals/${approval.id}/decision`, {
    token: TWO,
    headers: { 'idempotency-key': key },
    body: { grant: true },
  })
  const second = await h().request('POST', `/v1/approvals/${approval.id}/decision`, {
    token: TWO,
    headers: { 'idempotency-key': key },
    body: { grant: true },
  })
  assert.equal(first.status, 201)
  assert.equal(second.status, 200)
  assert.equal(h().ledger.reversals.length, 1, 'the upstream must be called once')
  assert.equal((await sql!`select seq from audit_events where action = 'admin.approval.executed'`).length, 1)
})

/* ------------------------------------------------------------------ the audit mirror */

/**
 * Signed the way a real producer signs.
 *
 * `signDelivery` from `contracts-events` — the SAME function every outbox relay in the estate
 * calls — rather than a MAC recomputed from this file's own idea of the format. That distinction
 * is the whole defect: the old helper here reimplemented `sha256=<hmac(body)>`, agreed perfectly
 * with the route it was testing, and agreed with nothing that actually sends events.
 */
function sign(body: unknown): { raw: string; signature: string } {
  const raw = JSON.stringify(body)
  return { raw, signature: signDelivery(raw, SIGNING_SECRET) }
}

/**
 * A REAL domain envelope, not a bespoke audit document.
 *
 * The fixture used to be a `ledger.audit.recorded` event carrying an `action`, a `subjectKind` and
 * an `actor` in its payload — a shape nothing in the estate has ever emitted. That is the defect:
 * the mirror was a consumer with no producer, so this suite was green against an imaginary
 * counterparty. This is `ledger.entry.posted` as `contracts-events`' own `makeEvent` builds it,
 * and `validateEnvelope` accepts it, which is what makes the intake tested against reality.
 */
function mirrorEnvelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: '77777777-7777-4777-8777-777777777777',
    topic: 'ledger.entry.posted',
    // The subject id. `TopicSpec.keyedBy` already says what it holds for every topic.
    key: 'entry-1',
    occurredAt: '2026-08-01T00:00:00.000Z',
    producer: 'ledger',
    version: '1.0',
    // The actor is the ENVELOPE's, required by `validateEnvelope`. It was a payload field before,
    // which is how an unsigned producer could have named any operator it liked.
    actor: OPERATOR_ONE,
    correlationId: 'req-mirror',
    payload: { amount: '1000' },
    ...overrides,
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE DEFECT THIS SUITE EXISTS FOR.
//
// Every case below used to pass `token: MIRROR` and sign with a local reimplementation of a
// format nothing sends. So the suite was green against a caller that does not exist, speaking a
// dialect nobody speaks, while the estate's audit of record received nothing at all — and an
// empty operator timeline during an incident looks like an answer.
//
// What is exercised now is what is on the wire: `signDelivery`, `cf-signature`, no Authorization.
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('THE MIRROR ACCEPTS A RELAY DELIVERY WITH NO AUTHORIZATION HEADER AT ALL', { skip }, async () => {
  // Against the previous build this answered 401 — twice over, for two independent reasons —
  // measured against the running estate as well as here.
  const signed = sign(mirrorEnvelope())
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 201, 'a correctly signed mirror row with no bearer must be recorded')

  const rows = await sql!<{ actor: string; action: string; source: string; source_event_id: string }[]>`
    select actor, action, source, source_event_id from audit_events
  `
  assert.equal(rows.length, 1, 'THE AUDIT MIRROR ACTUALLY RECEIVED THE EVENT')
  assert.equal(rows[0]?.actor, OPERATOR_ONE)
  // The action IS the topic name. `<service>.<aggregate>.<past-tense-verb>` was already both the
  // topic naming rule and this service's documented `action` format; nothing invents a string.
  assert.equal(rows[0]?.action, 'ledger.entry.posted')
  // The source is the envelope's producer. `validateEnvelope` is what constrains it: it requires
  // the producer to own the topic namespace, so `ledger` cannot carry an `identity.*` topic.
  assert.equal(rows[0]?.source, 'ledger')
  assert.equal((await verifyChain(sql!, { from: 0n })).ok, true)
})

test('THE SIGNATURE IS THE ESTATE SCHEME: the retired local format is refused', { skip }, async () => {
  // The other half of the defect, pinned so it cannot come back. `sha256=<hmac(body)>` over the
  // right bytes with the right secret — everything the old route wanted — and it is refused,
  // because it carries no timestamp and therefore no replay window.
  const raw = JSON.stringify(mirrorEnvelope())
  const legacy = `sha256=${createHmac('sha256', SIGNING_SECRET).update(raw).digest('hex')}`
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: legacy, 'content-type': 'application/json' },
    body: raw,
  })
  assert.equal(res.status, 401)
  assert.equal(res.body.error.code, 'bad_signature')
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('A STALE SIGNATURE IS REFUSED — the replay window the old scheme did not have', { skip }, async () => {
  // A captured POST to the audit intake used to stay valid for ever, on the one record a dispute
  // is settled against. `now` is an injected seam, not the wall clock, so this cannot go red on a
  // slow machine or green on a fast one.
  const signedAt = Date.now() - (DELIVERY_TOLERANCE_MS + 60_000)
  const raw = JSON.stringify(mirrorEnvelope())
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signDelivery(raw, SIGNING_SECRET, signedAt), 'content-type': 'application/json' },
    body: raw,
  })
  assert.equal(res.status, 401)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('AN UNSIGNED MIRROR ROW IS REFUSED, and is not parsed', { skip }, async () => {
  const res = await h().request('POST', '/v1/events', { body: mirrorEnvelope() })
  assert.equal(res.status, 401)
  assert.equal(res.body.error.code, 'bad_signature')
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('a WRONGLY signed mirror row is refused', { skip }, async () => {
  const envelope = mirrorEnvelope()
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: 'sha256=deadbeef' },
    body: envelope,
  })
  assert.equal(res.status, 401)
})

test('a signature over DIFFERENT bytes is refused', { skip }, async () => {
  // The signature must cover the exact bytes received, or a body can be swapped after signing.
  const signed = sign(mirrorEnvelope())
  const tampered = JSON.stringify(mirrorEnvelope({ payload: { ...(mirrorEnvelope()['payload'] as object), actor: OPERATOR_TWO } }))
  assert.notEqual(tampered, signed.raw, 'the fixture must actually differ or this asserts nothing')
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: tampered,
  })
  assert.equal(res.status, 401)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('A BEARER BUYS NOTHING HERE: the MAC is the whole authentication', { skip }, async () => {
  // The direction that catches a future edit "restoring" the token check by making the signature
  // optional when a bearer is present. A reader token is a real, valid credential on this service.
  const res = await h().request('POST', '/v1/events', {
    token: READER,
    body: mirrorEnvelope(),
  })
  assert.equal(res.status, 401)
  assert.equal(res.body.error.code, 'bad_signature')
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

/* ------------------------------------------------ the rotation overlap window, end to end */

/**
 * **THE PROPERTY A ROLLING ROTATION DEPENDS ON.**
 *
 * `OUTBOX_SIGNING_SECRET` is one shared key across the estate. Rotating it means every producer
 * and every receiver changes on the same day, and during that day some producers are still signing
 * with the old key. If this route accepted only the new one, their deliveries would 401 — and the
 * thing that goes quiet is the estate's audit of record, which during an incident is indistinguishable
 * from "nothing happened".
 *
 * So: the NEW secret leads the accept list, the delivery is signed with the SUPERSEDED one, and it
 * must still be recorded. A dedicated harness because the accept list is fixed at construction.
 */
test('A DELIVERY SIGNED WITH THE SUPERSEDED SECRET IS STILL ACCEPTED WHILE THE NEW ONE LEADS', { skip }, async () => {
  const rotating = await startHarness(sql!, verifier!, {
    acceptSecrets: [ROTATED_SECRET, SIGNING_SECRET],
    readiness: fakeReadiness({ ledger: { ready: true, state: 'ready' } }),
  })
  try {
    const raw = JSON.stringify(mirrorEnvelope())
    const res = await rotating.request('POST', '/v1/events', {
      // Signed with the OLD key, which is what a producer that has not been redeployed yet sends.
      headers: { [SIGNATURE_HEADER]: signDelivery(raw, SIGNING_SECRET), 'content-type': 'application/json' },
      body: raw,
    })
    assert.equal(res.status, 201, 'a producer still on the superseded secret must not be partitioned off')
    assert.equal((await sql!`select seq from audit_events`).length, 1)
  } finally {
    await rotating.close()
  }
})

test('A SECRET THAT IS NOT ON THE ACCEPT LIST IS STILL REFUSED', { skip }, async () => {
  // The other direction. Accepting a list must not become accepting anything: once the old secret
  // is dropped from the list, deliveries signed with it stop — which is what completes a rotation.
  const rotated = await startHarness(sql!, verifier!, {
    acceptSecrets: [ROTATED_SECRET],
    readiness: fakeReadiness({ ledger: { ready: true, state: 'ready' } }),
  })
  try {
    const raw = JSON.stringify(mirrorEnvelope())
    const res = await rotated.request('POST', '/v1/events', {
      headers: { [SIGNATURE_HEADER]: signDelivery(raw, SIGNING_SECRET), 'content-type': 'application/json' },
      body: raw,
    })
    assert.equal(res.status, 401)
    assert.equal(res.body.error.code, 'bad_signature')
    assert.equal((await sql!`select seq from audit_events`).length, 0)
  } finally {
    await rotated.close()
  }
})

test('a redelivered mirror row lands ONCE', { skip }, async () => {
  const signed = sign(mirrorEnvelope())
  const send = () =>
    h().request('POST', '/v1/events', {

      headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
      body: signed.raw,
    })
  assert.equal((await send()).status, 201)
  const again = await send()
  // 200, not an error: at-least-once delivery guarantees this, and answering 4xx would make a
  // correctly-behaving producer retry for ever.
  assert.equal(again.status, 200)
  assert.equal(again.body.status, 'duplicate')
  assert.equal((await sql!`select seq from audit_events`).length, 1)
})

test('a mirror row with no principal actor is 400', { skip }, async () => {
  // The actor is now an ENVELOPE field, and `validateEnvelope` refuses one that is not
  // `system` or `<kind>:<id>`. Before, it was a payload field a producer supplied freely.
  const envelope = mirrorEnvelope({ actor: 'nobody' })
  const signed = sign(envelope)
  const res = await h().request('POST', '/v1/events', {

    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /actor/)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE OTHER TWO ACTOR KINDS, AT THE ROUTE. micro-org#265.
//
// The comment three tests above already says it: `validateEnvelope` refuses an actor that is not
// `system` or `<kind>:<id>`. It has said so the whole time, and every mirror case in this file
// nonetheless used `OPERATOR_ONE`, which is `user:<uuid>` — so `system` and `operator:` were
// documented as legal here and exercised nowhere, while `audit_events_actor_is_a_principal`
// admitted only `user:` and `service:`. The two halves disagreed and no test could see it.
//
// What that cost, measured on mainnet on 2026-08-08: 863 `ledger.reconciliation.completed` (a
// leased job, so `ledger/src/outbox.ts:201` substitutes `system`) and 10 `ledger.entry.posted`
// carrying `operator:drift-correction` — both audited topics — met a CHECK violation, an
// unhandled 500, and a producer breaker that opened. None of the 873 is in the log of record.
//
// So the acceptance is asserted here, at the intake, and not only against the constraint: the
// path that failed was route → `auditRowFor` → insert, and a constraint test alone would not have
// caught a route that answers 500 rather than recording the row.
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('THE MIRROR RECORDS A SYSTEM ACTOR — a leased job is a principal', { skip }, async () => {
  const signed = sign(
    mirrorEnvelope({
      id: '88888888-8888-4888-8888-888888888888',
      topic: 'ledger.reconciliation.completed',
      key: 'ethereum:mainnet',
      actor: 'system',
    }),
  )
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 201, 'against the previous build this was a 500 and the row was lost')
  const rows = await sql!<{ actor: string; action: string }[]>`select actor, action from audit_events`
  assert.deepEqual(
    rows.map((r) => ({ actor: r.actor, action: r.action })),
    [{ actor: 'system', action: 'ledger.reconciliation.completed' }],
  )
})

test('THE MIRROR RECORDS AN OPERATOR ACTOR — the drift corrections that were lost', { skip }, async () => {
  const signed = sign(mirrorEnvelope({ actor: 'operator:drift-correction' }))
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 201)
  const rows = await sql!<{ actor: string }[]>`select actor from audit_events`
  assert.deepEqual(
    rows.map((r) => r.actor),
    ['operator:drift-correction'],
  )
})

test('a mirror row with no correlation id is 400 — an investigation stops there', { skip }, async () => {
  const signed = sign(mirrorEnvelope({ correlationId: '' }))
  const res = await h().request('POST', '/v1/events', {

    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /correlationId/)
})

/**
 * **WHAT WAS GIVEN UP, ASSERTED RATHER THAN QUIETLY DROPPED.**
 *
 * There used to be a test here called "A SERVICE MAY NOT MIRROR ANOTHER SERVICE ROWS": emberkin
 * held the mirror scope, posted a `ledger.*` envelope, and was refused because the SIGNED producer
 * disagreed with the AUTHENTICATED sender. That check is gone with the bearer — with no second,
 * independent statement of who is on the connection, it would have compared `event.producer` to
 * itself, and a guard that compares a value to a copy of itself cannot fail.
 *
 * It is not enough to delete it silently, so this asserts what DOES still constrain the source:
 * `validateEnvelope`'s requirement that a producer own its topic namespace. The residual risk is
 * recorded in `server.ts` — any holder of the estate outbox secret can mirror a row attributed to
 * any producer, and the fix that restores the distinction is a per-producer signing secret, which
 * is a `micro-deploy` and `contracts-events` change.
 */
test('THE PRODUCER MUST OWN THE TOPIC NAMESPACE — what still constrains `source`', { skip }, async () => {
  // emberkin claiming a ledger topic. Correctly signed with the estate secret, so the MAC is no
  // help here; it is the envelope contract that refuses it.
  const signed = sign(mirrorEnvelope({ producer: 'emberkin' }))
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 400)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('an UNREGISTERED topic is accepted and ignored rather than refused', { skip }, async () => {
  // A producer subscribing this service to a topic it does not consume is a configuration mistake;
  // answering 4xx would make its relay retry for ever over something harmless. And the honest
  // reading of a topic this build does not know is that THIS service is behind, not that the
  // producer is wrong — contracts-events is additive-only.
  const signed = sign(mirrorEnvelope({ topic: 'ledger.widget.frobnicated' }))
  const res = await h().request('POST', '/v1/events', {

    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 202)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('a REGISTERED topic the audit log does not carry is also ignored', { skip }, async () => {
  // A battle resolving is a real, registered, correctly-signed event that the operator log
  // deliberately excludes — `TOPIC_AUDIT` records why for every one of the fifteen. The two
  // ignore paths are distinct and both must be 202: one is "this service is behind", the other is
  // "this was decided", and a future reader must be able to tell them apart from the metric label.
  const signed = sign(
    mirrorEnvelope({ topic: 'emberkin.battle.resolved', producer: 'emberkin', key: 'battle-1' }),
  )
  const res = await h().request('POST', '/v1/events', {

    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 202)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('A MONEY EVENT IS FINDABLE BY THE CORRELATION ID THE USER QUOTED', { skip }, async () => {
  // 17 §7 claim 9, end to end and through HTTP: ledger posts an entry, the mirror records it, and
  // an operator finds it by the id the user pasted. This could not pass at all before — the topic
  // the intake keyed on had no producer anywhere in the estate.
  const signed = sign(mirrorEnvelope({ correlationId: 'req-user-quoted' }))
  assert.equal(
    (
      await h().request('POST', '/v1/events', {
        headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
        body: signed.raw,
      })
    ).status,
    201,
  )
  const page = await h().request('GET', '/v1/audit?correlationId=req-user-quoted', { token: READER })
  assert.equal(page.status, 200)
  assert.equal(page.body.events.length, 1)
  assert.equal(page.body.events[0].action, 'ledger.entry.posted')
  assert.equal(page.body.events[0].subjectKind, 'ledger_entry')
  assert.equal(page.body.events[0].subjectId, 'entry-1')
  assert.equal(page.body.events[0].source, 'ledger')
})

test('a mirror row with a non-uuid id is 400', { skip }, async () => {
  const signed = sign(mirrorEnvelope({ id: 'not-a-uuid' }))
  const res = await h().request('POST', '/v1/events', {

    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(res.status, 400)
})

/* ------------------------------------------------------------------ audit reads */

test('the audit route pages and filters', { skip }, async () => {
  for (let i = 0; i < 4; i++) await raise(ONE, { subjectId: `entry-${i}` })
  const page = await h().request('GET', '/v1/audit?limit=2', { token: READER })
  assert.equal(page.body.events.length, 2)
  assert.ok(page.body.nextCursor)
  const next = await h().request(`GET`, `/v1/audit?limit=2&before=${page.body.nextCursor}`, { token: READER })
  assert.equal(next.body.events.length, 2)
  // `seq` is a string on the wire: a bigint is not a JSON number.
  assert.equal(typeof page.body.events[0].seq, 'string')
})

test('a malformed cursor is 400, never a 500', { skip }, async () => {
  const res = await h().request('GET', '/v1/audit?before=yesterday', { token: READER })
  assert.equal(res.status, 400)
})

test('the verify route answers 200 whether or not the chain is intact', { skip }, async () => {
  await raise(ONE)
  const clean = await h().request('GET', '/v1/audit/verify?from=0', { token: READER })
  assert.equal(clean.status, 200)
  assert.equal(clean.body.ok, true)

  await sql!`update audit_events set actor = ${OPERATOR_TWO} where seq = 1`
  const broken = await h().request('GET', '/v1/audit/verify?from=0', { token: READER })
  // 200 with `ok: false`. A 500 would deny a monitoring system the fact it exists to read.
  assert.equal(broken.status, 200)
  assert.equal(broken.body.ok, false)
  assert.equal(broken.body.breaks[0].kind, 'hash_mismatch')
  assert.equal(broken.body.breaks[0].seq, '1')
})

/* ------------------------------------------------------------------ flags */

test('a flag is created with an owner, and the change is audited both ways', { skip }, async () => {
  const created = await h().request('PUT', '/v1/flags/market.listing', {
    token: ONE,
    body: { enabled: false, description: 'Marketplace listing creation', owner: 'platform-team' },
  })
  assert.equal(created.status, 200)
  assert.equal(created.body.flag.enabled, false)
  assert.equal(created.body.flag.owner, 'platform-team')

  const flipped = await h().request('PUT', '/v1/flags/market.listing', {
    token: TWO,
    body: { enabled: true, description: 'Marketplace listing creation', owner: 'platform-team' },
  })
  assert.equal(flipped.body.changed, true)

  const audit = await sql!<{ action: string; actor: string; payload: any }[]>`
    select action, actor, payload from audit_events order by seq
  `
  assert.deepEqual(audit.map((r) => r.action), ['admin.flag.created', 'admin.flag.changed'])
  // "The flag is off" is not the useful fact six months later.
  assert.equal(audit[1]?.payload.before.enabled, false)
  assert.equal(audit[1]?.payload.after.enabled, true)
  assert.equal(audit[1]?.actor, OPERATOR_TWO)
})

test('a flag with no owner is refused', { skip }, async () => {
  const res = await h().request('PUT', '/v1/flags/orphan.flag', {
    token: ONE,
    body: { enabled: true, description: 'nobody owns this', owner: '   ' },
  })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /owner is required/)
})

test('a flag change emits an outbox event, in the same transaction', { skip }, async () => {
  await h().request('PUT', '/v1/flags/market.listing', {
    token: ONE,
    body: { enabled: true, description: 'd', owner: 'platform' },
  })
  const events = await sql!<{ topic: string; key: string }[]>`select topic, key from outbox`
  assert.equal(events.length, 1)
  assert.equal(events[0]?.topic, 'admin.flag.changed')
})

test('a flag key that is not a key shape is refused', { skip }, async () => {
  const res = await h().request('PUT', '/v1/flags/Not%20A%20Key', {
    token: ONE,
    body: { enabled: true, description: 'd', owner: 'platform' },
  })
  assert.equal(res.status, 500, 'a constraint violation reaches the generic handler')
  assert.equal((await sql!`select key from feature_flags`).length, 0)
})

/* ------------------------------------------------------------------ broadcasts */

test('a broadcast is published, listed live, and retracted rather than deleted', { skip }, async () => {
  const published = await h().request('POST', '/v1/broadcasts', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: { severity: 'maintenance', title: 'Ledger maintenance', body: 'Withdrawals pause for 20 minutes.' },
  })
  assert.equal(published.status, 201)
  const id = published.body.broadcast.id

  const live = await h().request('GET', '/v1/broadcasts?live=true', { token: READER })
  assert.equal(live.body.broadcasts.length, 1)

  const retracted = await h().request('DELETE', `/v1/broadcasts/${id}`, { token: TWO })
  assert.equal(retracted.status, 200)
  assert.equal(retracted.body.broadcast.retractedBy, OPERATOR_TWO)

  // ── Retracted, NOT deleted. "What did we tell users during the incident" is asked afterwards.
  const all = await h().request('GET', '/v1/broadcasts', { token: READER })
  assert.equal(all.body.broadcasts.length, 1)
  assert.equal((await h().request('GET', '/v1/broadcasts?live=true', { token: READER })).body.broadcasts.length, 0)
})

test('a second retraction is refused rather than audited twice', { skip }, async () => {
  const id = (
    await h().request('POST', '/v1/broadcasts', {
      token: ONE,
      headers: { 'idempotency-key': freshKey() },
      body: { severity: 'info', title: 't', body: 'b' },
    })
  ).body.broadcast.id
  await h().request('DELETE', `/v1/broadcasts/${id}`, { token: TWO })
  const again = await h().request('DELETE', `/v1/broadcasts/${id}`, { token: TWO })
  assert.equal(again.status, 400)
  assert.equal((await sql!`select seq from audit_events where action = 'admin.broadcast.retracted'`).length, 1)
})

test('an unknown severity is refused', { skip }, async () => {
  const res = await h().request('POST', '/v1/broadcasts', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: { severity: 'catastrophe', title: 't', body: 'b' },
  })
  assert.equal(res.status, 400)
})

test('a retracted broadcast that does not exist is 404', { skip }, async () => {
  const res = await h().request('DELETE', '/v1/broadcasts/99999999-9999-4999-8999-999999999999', { token: ONE })
  assert.equal(res.status, 404)
})

/* ------------------------------------------------------------------ GDPR erasure */

/**
 * `identity.user.deleted` as identity actually sends it: `{ userId, tombstoneAt, reason }` with the
 * envelope key set to the bare user id (`identity/src/deletion.ts`). The actor is the
 * operator who raised it, NOT the deleted user — which is the normal case for a support-raised
 * deletion and the case a handler reading `envelope.actor` gets wrong.
 */
const ERASED_USER = '018f0000-0000-7000-8000-0000000000aa'

function deletionEnvelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: '88888888-8888-4888-8888-888888888888',
    topic: 'identity.user.deleted',
    key: ERASED_USER,
    occurredAt: '2026-08-01T00:00:00.000Z',
    producer: 'identity',
    version: '1.0',
    actor: OPERATOR_ONE,
    correlationId: 'req-erasure',
    payload: {
      userId: ERASED_USER,
      tombstoneAt: '2026-09-01T00:00:00.000Z',
      reason: 'user_requested',
    },
    ...overrides,
  }
}

async function deliverDeletion(overrides: Record<string, unknown> = {}): Promise<number> {
  const signed = sign(deletionEnvelope(overrides))
  const res = await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  return res.status
}

test('ERASURE: the audit chain is NOT rewritten, and still verifies afterwards', { skip }, async () => {
  // ════════════════════════════════════════════════════════════════════════════════════════
  // The decision this whole design turns on. `audit_events` is a hash chain over `subject_id`
  // and `payload`, so rewriting either invalidates that row's hash and every hash after it —
  // and a chain that has been legitimately rewritten once is indistinguishable from one an
  // operator rewrote to cover a theft. The rows are RETAINED under Art. 17(3)(b) and (e), and
  // withheld from the read surface under Art. 18 instead. `src/erasure.ts` carries the argument.
  // ════════════════════════════════════════════════════════════════════════════════════════
  const signed = sign(
    mirrorEnvelope({
      id: '99999999-9999-4999-8999-999999999999',
      topic: 'identity.mfa.removed',
      producer: 'identity',
      key: ERASED_USER,
      payload: { method: 'totp' },
    }),
  )
  await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  const [before] = await sql!<{ n: string; h: string }[]>`
    select count(*) as n, max(hash) as h from audit_events`

  assert.equal(await deliverDeletion(), 201)

  // Not one hashed byte moved. The row about the erased user is still exactly the row that was
  // appended, which is the property that makes this log evidence.
  const [after] = await sql!<{ n: string }[]>`
    select count(*) as n from audit_events where subject_id = ${ERASED_USER}`
  assert.ok(Number(after?.n) >= 1, 'the audit rows about the subject were deleted')
  assert.equal((await verifyChain(sql!, { from: 0n })).ok, true, 'erasure broke the hash chain')
  assert.ok(before?.h)
})

test('ERASURE: the read surface withholds the subject and the mirrored payload', { skip }, async () => {
  const signed = sign(
    mirrorEnvelope({
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      topic: 'identity.mfa.removed',
      producer: 'identity',
      key: ERASED_USER,
      // The payload is a mirrored copy of a producer's envelope and is the only column here that
      // can carry an actual name or handle. It is the half that matters most.
      payload: { method: 'totp', handle: 'spiros' },
    }),
  )
  await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })

  const visible = await readAudit(sql!, { subjectKind: 'user', subjectId: ERASED_USER })
  assert.ok(visible.events.length >= 1, 'the fixture wrote no row, so this test proves nothing')
  assert.equal(visible.events[0]?.subjectId, ERASED_USER)
  assert.deepEqual(visible.events[0]?.payload, { method: 'totp', handle: 'spiros' })

  assert.equal(await deliverDeletion(), 201)

  const page = await readAudit(sql!, { subjectKind: 'user' })
  const mine = page.events.filter((e: AuditRow) => e.action === 'identity.mfa.removed')
  assert.ok(mine.length >= 1)
  for (const row of mine) {
    assert.equal(row.subjectId, 'erased:restricted', 'the subject id was disclosed after erasure')
    assert.deepEqual(row.payload, {}, 'the mirrored payload was disclosed after erasure')
    // The actor is NOT restricted: it names the operator who acted, not the customer.
    assert.equal(row.actor, OPERATOR_ONE)
    // The hashes still read, because they are the evidence the chain is intact and a digest is
    // not a re-identification path.
    assert.match(row.hash, /^[0-9a-f]{64}$/)
  }
})

test('ERASURE: a non-user subject sharing the id is untouched', { skip }, async () => {
  // ════════════════════════════════════════════════════════════════════════════════════════
  // `audit_events.subject_id` is deliberately `text` and may name a ledger entry, a market case
  // or an on-chain hash (`migrations.ts`). Matching on the id alone would restrict — from
  // every operator read, during an incident — an audit row about a movement of money that no
  // data subject ever asked about. Only `subject_kind = 'user'` is in scope.
  // ════════════════════════════════════════════════════════════════════════════════════════
  const signed = sign(
    mirrorEnvelope({
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      topic: 'ledger.entry.posted',
      producer: 'ledger',
      // A ledger entry whose id happens to be the same string as the erased user's.
      key: ERASED_USER,
      payload: { amount: '1000' },
    }),
  )
  await h().request('POST', '/v1/events', {
    headers: { [SIGNATURE_HEADER]: signed.signature, 'content-type': 'application/json' },
    body: signed.raw,
  })
  assert.equal(await deliverDeletion(), 201)

  const ledgerRows = await readAudit(sql!, { subjectKind: 'ledger_entry' })
  const posted = ledgerRows.events.filter((e: AuditRow) => e.action === 'ledger.entry.posted')
  assert.ok(posted.length >= 1, 'the ledger fixture did not land')
  assert.equal(posted[0]?.subjectId, ERASED_USER, 'a ledger entry was restricted by a user erasure')
  assert.deepEqual(posted[0]?.payload, { amount: '1000' })

  // And the register itself refuses to hold anything but a user.
  await assert.rejects(
    () => sql!`
      insert into audit_subject_erasures (subject_kind, subject_id, source_event_id)
      values ('ledger_entry', ${ERASED_USER}, ${'cccccccc-cccc-4ccc-8ccc-cccccccccccc'})`,
    /audit_subject_erasures_user_only/,
  )
})

test('ERASURE: an approval about the user is anonymised, and four eyes survive', { skip }, async () => {
  // `approvals` is NOT hash-chained, so the subject CAN be genuinely de-linked rather than merely
  // restricted. What must survive is the four-eyes evidence — two distinct operators — and that
  // does not need to know which customer the action was about.
  const requested = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: {
      // The only action in the registry whose subject IS a user (`actions.ts`); every other
      // one names a ledger entry, a moderation case or an entitlement. `subject_kind` comes from
      // the action rather than from the body, which is what makes that true rather than hoped.
      action: 'identity.role.grant',
      subjectId: ERASED_USER,
      params: { role: 'admin' },
      reasonCode: 'regulatory_request',
      reason: 'granting the operator role after an access review',
    },
  })
  assert.equal(requested.status, 201)

  assert.equal(await deliverDeletion(), 201)

  const [approval] = await sql!<{ subject_id: string; requested_by: string }[]>`
    select subject_id, requested_by from approvals`
  assert.equal(approval?.subject_id, 'erased:restricted', 'the approval still names the customer')
  // The operator attribution is retained: an approval whose operators are anonymous cannot
  // evidence that two people were involved, which is the control the table exists to enforce.
  assert.equal(approval?.requested_by, OPERATOR_ONE)
})

test('ERASURE: the register is append-only and a redelivery is a duplicate', { skip }, async () => {
  assert.equal(await deliverDeletion(), 201)
  // Same event id: the inbox dedupes it, so nothing is registered twice.
  assert.equal(await deliverDeletion(), 200)

  const rows = await sql!<{ subject_id: string }[]>`select subject_id from audit_subject_erasures`
  assert.equal(rows.length, 1)

  // An erasure is a fact, not configuration. Every restriction on the read path derives from this
  // table, so a DELETE here would silently re-expose every audit row about that person.
  await assert.rejects(
    () => sql!`delete from audit_subject_erasures where subject_id = ${ERASED_USER}`,
    /append-only/,
  )
  await assert.rejects(
    () => sql!`update audit_subject_erasures set subject_id = 'someone-else'`,
    /append-only/,
  )
})

/* ------------------------------------------------------------------ bodies */

test('a body that is not JSON is 400', { skip }, async () => {
  const res = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': freshKey(), 'content-type': 'application/json' },
    body: '{not json',
  })
  assert.equal(res.status, 400)
})

test('an oversized body is refused before it is buffered', { skip }, async () => {
  const res = await h().request('POST', '/v1/approvals', {
    token: ONE,
    headers: { 'idempotency-key': freshKey() },
    body: { action: 'ledger.entry.reverse', subjectId: 'e', params: { description: 'x'.repeat(400_000) }, reasonCode: 'data_correction', reason: 'r' },
  })
  assert.equal(res.status, 400)
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
   THE BACKUP SURFACE IS OPERATOR-ONLY, INCLUDING ITS READS.

   `admin` is `adminOnly` in `ui/packages/ui/src/surfaces.ts`, but that flag is a NAVIGATION filter
   — `admin-web/src/lib/auth.tsx:4` says so in as many words, and `ProtectedRoute` only checks that
   a session exists. This is the boundary, and these tests are what prove it holds.

   Note what is NOT here: a `READER` case that succeeds. Every other read on this service admits a
   service token holding the exact `admin:read` scope; these deliberately do not. A backup listing
   names the directory the artefacts live in, the databases they cover and the checksums that
   authenticate them — a map of where the estate's data is kept — and a read-only service
   credential is a credential that sits in a container's environment. An unauthenticated restore is
   a total compromise, and the read is most of the way to one.
   ══════════════════════════════════════════════════════════════════════════════════════════════ */

/** A GET may not carry a body; a mutating route needs one and an Idempotency-Key. */
function bodyFor(method: string): { headers: Record<string, string>; body?: unknown } {
  const headers = { 'idempotency-key': 'this-caller-should-never-get-this-far' }
  if (method === 'GET') return { headers }
  return {
    headers,
    body: { backupRunId: '11111111-1111-1111-1111-111111111111', mode: 'verify', rootPath: '/tmp' },
  }
}

const BACKUP_ROUTES = [
  ['GET', '/v1/backups'],
  ['GET', '/v1/backups/settings'],
  ['PUT', '/v1/backups/settings'],
  ['GET', '/v1/backups/11111111-1111-1111-1111-111111111111'],
  ['POST', '/v1/backups'],
  ['GET', '/v1/restores'],
  ['POST', '/v1/restores'],
] as const

test('an ordinary user without role:admin cannot reach ANY backup route', { skip }, async () => {
  for (const [method, path] of BACKUP_ROUTES) {
    // A valid key on the mutating ones, so the refusal cannot be mistaken for the 400 that a
    // missing Idempotency-Key would produce. The 403 must come from the ROLE.
    const res = await h().request(method, path, { token: PLAYER, ...bodyFor(method) })
    assert.equal(res.status, 403, `${method} ${path} must be 403 for a non-admin`)
    assert.match(res.body.error.message, /role:admin/, `${method} ${path}`)
  }
})

test('a SERVICE token cannot reach the backup surface even holding admin:read', { skip }, async () => {
  for (const [method, path] of BACKUP_ROUTES) {
    const res = await h().request(method, path, { token: READER, ...bodyFor(method) })
    assert.equal(res.status, 403, `${method} ${path} must refuse a service token`)
    assert.match(res.body.error.message, /role:admin/, `${method} ${path}`)
  }
})

test('an unauthenticated caller reaches nothing on the backup surface', { skip }, async () => {
  for (const [method, path] of BACKUP_ROUTES) {
    const res = await h().request(method, path, bodyFor(method))
    assert.equal(res.status, 401, `${method} ${path} must be 401 without a token`)
  }
})

/**
 * The live restore has exactly one door, and this is the test that says so.
 *
 * An operator holding `role:admin` — the strongest credential on this surface — still cannot cause
 * a live restore through the direct route. The refusal names the queue rather than being a bare
 * 400, because an operator during an incident needs to be told where to go, not merely stopped.
 */
test('even an ADMIN cannot request a live restore directly; the queue is the only door', { skip }, async () => {
  const res = await h().request('POST', '/v1/restores', {
    token: ONE,
    headers: { 'idempotency-key': 'an-admin-trying-the-direct-route' },
    body: { backupRunId: '11111111-1111-1111-1111-111111111111', mode: 'live', reason: 'incident' },
  })
  assert.equal(res.status, 400)
  assert.match(res.body.error.message, /estate\.restore approval/)
  assert.match(res.body.error.message, /second operator/)
})
