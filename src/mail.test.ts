/**
 * The operator mail view, over HTTP.
 *
 * The assertion that carries this file is the BEARER one. These routes forward the operator's own
 * token to notify rather than minting a service token, for two reasons that a reader six months
 * from now will otherwise undo:
 *
 *   1. Notify's `/admin/deliveries` routes are `requireAdmin` and refuse a service principal
 *      outright, so a service token 403s. That is a runtime failure a unit test with a permissive
 *      fake would never see.
 *   2. Resending somebody's mail is an act by a named human. Forwarding the token they already
 *      presented keeps the authorisation decision in notify, against the real person, rather than
 *      recording every action as "admin-api did it".
 *
 * `fakeNotify` therefore records every bearer it is handed, and the tests below read it back.
 */

import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import {
  ALICE,
  type Harness,
  enabled,
  fakeVerifier,
  freshKey,
  migrateTestDb,
  openDb,
  operatorPrincipal,
  resetAdminApi,
  servicePrincipal,
  skip,
  startHarness,
} from './testsupport.ts'

const sql = enabled ? openDb() : null

before(async () => {
  if (sql) await migrateTestDb(sql)
})

after(async () => {
  if (sql) await sql.end()
})

const delivery = (over: Record<string, unknown> = {}) => ({
  id: '77777777-7777-4777-8777-777777777777',
  userId: ALICE,
  channel: 'email',
  state: 'sent',
  outcome: 'sent',
  reason: null,
  attempts: 1,
  maxAttempts: 6,
  lastError: null,
  category: 'account',
  templateId: 'account.verify_email',
  createdAt: '2026-08-12T13:03:16.000Z',
  sentAt: '2026-08-12T13:03:20.000Z',
  ...over,
})

test("the operator's OWN bearer reaches notify, not a service token", { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    harness.notify.seed([delivery()])
    const res = await harness.request('GET', `/v1/mail?user=${ALICE}`, { token: 'operator-bearer' })
    assert.equal(res.status, 200)

    // The whole point. A switch to `{ kind: 'service' }` would still return 200 here against a
    // permissive fake and then 403 against the real notify, which refuses service principals.
    assert.deepEqual(harness.notify.bearers, ['operator-bearer'])
  } finally {
    await harness.close()
  }
})

test('a successful send is returned, not just failures', { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    // Support's question is "did it arrive", and `sent` is most of that answer. Notify's
    // dead-letter default would have hidden this row and left an empty list meaning both
    // "nothing failed" and "nothing was sent".
    harness.notify.seed([delivery({ state: 'sent' })])
    const res = await harness.request('GET', `/v1/mail?user=${ALICE}`, { token: 'operator-bearer' })
    const body = res.body as { deliveries: readonly { state: string }[] }
    assert.equal(body.deliveries.length, 1)
    assert.equal(body.deliveries[0]?.state, 'sent')
  } finally {
    await harness.close()
  }
})

test('an unscoped query is refused rather than answered with the whole estate', { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    // Unscoped, notify's route is the estate-wide dead-letter view — a different question. Serving
    // it under a name that promises one person's mail is the kind of quiet mismatch an operator
    // acts on without noticing.
    const res = await harness.request('GET', '/v1/mail', { token: 'operator-bearer' })
    assert.equal(res.status, 400)
    assert.deepEqual(harness.notify.bearers, [], 'notify must not be called at all')
  } finally {
    await harness.close()
  }
})

test('resend answers 202 and names the NEW delivery', { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    const id = '77777777-7777-4777-8777-777777777777'
    const res = await harness.request('POST', `/v1/mail/${id}/resend`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })

    // 202, not 200: nothing has been sent when this returns. Notify queues a second delivery and
    // the dispatcher takes it on its own schedule, so a 200 would claim a delivery that has not
    // happened — and the operator would stop watching.
    assert.equal(res.status, 202)
    assert.deepEqual(harness.notify.resent, [id])
    assert.equal((res.body as { deliveryId: string }).deliveryId, `resent-${id}`)
    assert.deepEqual(harness.notify.bearers, ['operator-bearer'])
  } finally {
    await harness.close()
  }
})

test('a read-scoped SERVICE token may look, but may not resend', { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({
    'operator-bearer': operatorPrincipal(ALICE),
    'service-bearer': servicePrincipal('support-tool', ['admin:read']),
  })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    harness.notify.seed([delivery()])

    // Reading is `requireReader`: answering "I never got the email" should not need the authority
    // to reverse a ledger entry.
    const read = await harness.request('GET', `/v1/mail?user=${ALICE}`, { token: 'service-bearer' })
    assert.equal(read.status, 200)

    // Resending puts a message in front of a person. That is an operator's act, and a read-scoped
    // service token must not be able to perform it.
    const write = await harness.request('POST', `/v1/mail/${delivery().id}/resend`, {
      token: 'service-bearer',
      headers: { 'idempotency-key': freshKey() },
    })
    assert.equal(write.status, 403)
    assert.deepEqual(harness.notify.resent, [], 'nothing was queued')
  } finally {
    await harness.close()
  }
})

test('a retried resend replays instead of sending a SECOND email', { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    const id = '77777777-7777-4777-8777-777777777777'
    const key = freshKey()
    const send = () =>
      harness.request('POST', `/v1/mail/${id}/resend`, {
        token: 'operator-bearer',
        headers: { 'idempotency-key': key },
      })

    const first = await send()
    const second = await send()

    // Notify refuses to resend a delivery that is already `pending`, which stops a double click
    // on the same row. It does NOT stop this: a retried request resends the original — still
    // dead, still eligible — and would queue a second delivery. Two messages to one person for
    // one operator action. `routeidempotency.test.ts` caught exactly this before it shipped.
    assert.equal(first.status, 202)
    assert.equal(second.status, 202)
    assert.deepEqual(harness.notify.resent, [id], 'notify was asked ONCE')
    assert.deepEqual(first.body, second.body, 'the replay returns the first answer')
  } finally {
    await harness.close()
  }
})
