/**
 * Outbox, relay, inbox and idempotency.
 *
 * No broker: Postgres outbox → signed HTTP → inbox, deduped. AD-10 records the four measured
 * conditions under which that stops being the right answer.
 *
 * The inbox on THIS service is the estate's audit mirror, so its dedupe is not hygiene: a
 * redelivered mirror row would put a privileged action into the audit of record twice, and an
 * operator counting signatures would get the wrong number.
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  createRelay,
  emitOn,
  signEvent,
  verifyEventSignature,
  withInbox,
  type Db,
} from './outbox.ts'
import {
  IdempotencyInFlightError,
  IdempotencyKeyReuseError,
  namespacedKey,
  reapIdempotencyKeys,
  requestFingerprint,
  withIdempotency,
} from './idempotency.ts'
import {
  OPERATOR_ONE,
  OPERATOR_TWO,
  db,
  enabled,
  migrateTestDb,
  openDb,
  quietLogger,
  resetAdminApi,
  skip,
} from './testsupport.ts'

const SECRET = 'a-test-signing-secret-of-sufficient-length'
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

/* ------------------------------------------------------------------ signing */

test('a signature verifies over the exact bytes and nothing else', () => {
  const body = JSON.stringify({ topic: 'admin.flag.changed', key: 'a' })
  const signature = signEvent(body, SECRET)
  assert.equal(verifyEventSignature(body, SECRET, signature), true)
  assert.equal(verifyEventSignature(`${body} `, SECRET, signature), false)
  assert.equal(verifyEventSignature(body, 'another-secret-of-sufficient-length', signature), false)
})

test('a signature of the wrong LENGTH is refused without a comparison', () => {
  // `timingSafeEqual` throws on mismatched lengths, so the length is checked first — and a
  // byte-at-a-time comparison of a MAC is a byte-at-a-time forgery oracle.
  const body = '{}'
  assert.equal(verifyEventSignature(body, SECRET, 'sha256=short'), false)
  assert.equal(verifyEventSignature(body, SECRET, ''), false)
})

test('a Buffer and a string sign identically', () => {
  const body = '{"a":1}'
  const signature = signEvent(body, SECRET)
  assert.equal(verifyEventSignature(Buffer.from(body, 'utf8'), SECRET, signature), true)
})

/* ------------------------------------------------------------------ the outbox */

test('an event is written in the caller\'s transaction, or not at all', { skip }, async () => {
  await assert.rejects(async () =>
    sql!.begin(async (tx) => {
      await emitOn(tx, 'admin-api', { topic: 'admin.flag.changed', key: 'a', payload: {} })
      throw new Error('the domain change failed')
    }),
  )
  assert.equal((await sql!`select id from outbox`).length, 0)
})

test('an event carries its actor and correlation id', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await emitOn(tx, 'admin-api', {
      topic: 'admin.flag.changed',
      key: 'market.listing',
      actor: OPERATOR_ONE,
      correlationId: 'req-1',
      payload: { enabled: true },
    })
    return { value: null }
  })
  const rows = await sql!<{ actor: string; correlation_id: string; producer: string }[]>`
    select actor, correlation_id, producer from outbox
  `
  assert.equal(rows[0]?.actor, OPERATOR_ONE)
  assert.equal(rows[0]?.correlation_id, 'req-1')
  assert.equal(rows[0]?.producer, 'admin-api')
})

/* ------------------------------------------------------------------ the relay */

function jobAndCtx() {
  return [
    { id: '00000000-0000-4000-8000-000000000000', kind: 'outbox.relay', key: 'outbox', attempts: 1, maxAttempts: 5, payload: {} },
    { heartbeat: async () => true, signal: new AbortController().signal },
  ] as const
}

async function seedEvent(topic = 'admin.flag.changed'): Promise<void> {
  await sql!.begin(async (tx) => {
    await emitOn(tx, 'admin-api', { topic, key: 'k', payload: { a: 1 } })
    return { value: null }
  })
}

test('the relay delivers to every active subscription and signs the body', { skip }, async () => {
  await seedEvent()
  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/one')`

  const seen: Array<{ body: unknown; headers: Record<string, string> }> = []
  const relay = createRelay({
    sql: db(sql!),
    logger: quietLogger(),
    signingSecret: SECRET,
    clientFor: () => ({
      async request(_path, options) {
        seen.push({ body: options?.body, headers: (options?.headers ?? {}) as Record<string, string> })
        return undefined as never
      },
    }),
  })
  const [job, ctx] = jobAndCtx()
  await relay(job, ctx)

  assert.equal(seen.length, 1)
  const signature = seen[0]!.headers['x-cloudsforge-signature']!
  // Signed over the exact bytes the client will send, so the MAC a subscriber recomputes matches.
  assert.equal(verifyEventSignature(JSON.stringify(seen[0]!.body), SECRET, signature), true)
  assert.equal((await sql!`select id from outbox where published_at is not null`).length, 1)
})

test('an inactive subscription receives nothing, and the event still publishes', { skip }, async () => {
  await seedEvent()
  await sql!`insert into event_subscriptions (topic, url, active) values ('admin.flag.changed', 'http://sub/off', false)`
  let calls = 0
  const relay = createRelay({
    sql: db(sql!),
    logger: quietLogger(),
    signingSecret: SECRET,
    clientFor: () => ({ async request() { calls += 1; return undefined as never } }),
  })
  const [job, ctx] = jobAndCtx()
  await relay(job, ctx)
  assert.equal(calls, 0)
  assert.equal((await sql!`select id from outbox where published_at is not null`).length, 1)
})

test('ONE UNREACHABLE SUBSCRIBER DOES NOT STOP THE OTHERS', { skip }, async () => {
  await seedEvent()
  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/dead')`
  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/live')`

  const delivered: string[] = []
  const relay = createRelay({
    sql: db(sql!),
    logger: quietLogger(),
    signingSecret: SECRET,
    clientFor: (url) => ({
      async request() {
        if (url.includes('dead')) throw new Error('ECONNREFUSED')
        delivered.push(url)
        return undefined as never
      },
    }),
  })
  const [job, ctx] = jobAndCtx()
  await relay(job, ctx)

  assert.deepEqual(delivered, ['http://sub/live'])
  // The event stays UNPUBLISHED while a delivery is outstanding, so the next pass retries it.
  assert.equal((await sql!`select id from outbox where published_at is null`).length, 1)
  const failed = await sql!<{ last_error: string }[]>`
    select last_error from outbox_deliveries where last_error is not null
  `
  assert.match(failed[0]?.last_error ?? '', /ECONNREFUSED/)
})

test('a redelivery to an already-delivered subscription is skipped', { skip }, async () => {
  await seedEvent()
  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/one')`
  let calls = 0
  const relay = createRelay({
    sql: db(sql!),
    logger: quietLogger(),
    signingSecret: SECRET,
    clientFor: () => ({ async request() { calls += 1; return undefined as never } }),
  })
  const [job, ctx] = jobAndCtx()
  await relay(job, ctx)
  await relay(job, ctx)
  assert.equal(calls, 1)
})

const relayWith = (calls: string[], fail?: (url: string) => boolean) =>
  createRelay({
    sql: db(sql!),
    logger: quietLogger(),
    signingSecret: SECRET,
    clientFor: (url) => ({
      async request() {
        if (fail?.(url)) throw new Error('ECONNREFUSED')
        calls.push(url)
        return undefined as never
      },
    }),
  })

test('a subscriber added while an event is OUTSTANDING does receive it', { skip }, async () => {
  // Delivery rows are computed from the live subscription set on every pass rather than fixed when
  // the event was produced — so as long as something is still undelivered, a late subscriber is
  // picked up on the next pass.
  await seedEvent()
  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/dead')`
  const [job, ctx] = jobAndCtx()

  const first: string[] = []
  await relayWith(first, (url) => url.includes('dead'))(job, ctx)
  assert.deepEqual(first, [])
  assert.equal((await sql!`select id from outbox where published_at is null`).length, 1)

  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/late')`
  const second: string[] = []
  await relayWith(second, (url) => url.includes('dead'))(job, ctx)
  assert.deepEqual(second, ['http://sub/late'])
})

test('THE LIMIT: a subscriber added after the event PUBLISHED does not receive it', { skip }, async () => {
  // With zero active subscriptions the outstanding count is zero, so the event publishes on the
  // first pass and is never reconsidered. That is the right behaviour — a subscription is not a
  // replay request — but it is NOT what the comment inherited from market/src/outbox.ts:239-241
  // claims — nor what service-template/src/outbox.ts:205 claims, which is where market got it and
  // where seventeen other repositories got it too. Reported, not fixed: siblings are not ours.
  await seedEvent()
  const [job, ctx] = jobAndCtx()

  const first: string[] = []
  await relayWith(first)(job, ctx)
  assert.deepEqual(first, [], 'no subscribers yet')
  assert.equal((await sql!`select id from outbox where published_at is not null`).length, 1)

  await sql!`insert into event_subscriptions (topic, url) values ('admin.flag.changed', 'http://sub/late')`
  const second: string[] = []
  await relayWith(second)(job, ctx)
  assert.deepEqual(second, [], 'a published event is not replayed to a new subscriber')
})

/* ------------------------------------------------------------------ the inbox */

test('an inbound event runs its handler exactly once', { skip }, async () => {
  let runs = 0
  const handle = () =>
    withInbox(db(sql!), 'ledger.audit.recorded', '77777777-7777-4777-8777-777777777777', async () => {
      runs += 1
      return 'done'
    })
  assert.equal((await handle()).status, 'processed')
  assert.equal((await handle()).status, 'duplicate')
  assert.equal(runs, 1)
})

test('A FAILING HANDLER LEAVES NO INBOX ROW, so the redelivery is processed', { skip }, async () => {
  // The mistake a naive "record then handle" dedupe makes: the row lands, the handler fails, and
  // the redelivery is swallowed. Here the insert and the handler share one transaction.
  await assert.rejects(async () =>
    withInbox(db(sql!), 'ledger.audit.recorded', '77777777-7777-4777-8777-777777777777', async () => {
      throw new Error('the handler failed')
    }),
  )
  assert.equal((await sql!`select event_id from inbox`).length, 0)

  let ran = false
  const retried = await withInbox(db(sql!), 'ledger.audit.recorded', '77777777-7777-4777-8777-777777777777', async () => {
    ran = true
    return null
  })
  assert.equal(retried.status, 'processed')
  assert.equal(ran, true)
})

test('the same event id on two different topics is not a duplicate', { skip }, async () => {
  const id = '77777777-7777-4777-8777-777777777777'
  assert.equal((await withInbox(db(sql!), 'ledger.audit.recorded', id, async () => null)).status, 'processed')
  assert.equal((await withInbox(db(sql!), 'market.audit.recorded', id, async () => null)).status, 'processed')
})

/* ------------------------------------------------------------------ idempotency */

test('the fingerprint ignores per-attempt fields and nothing else', () => {
  const base = { action: 'ledger.entry.reverse', subjectId: 'e-1' }
  // A trace id is SUPPOSED to change per attempt. The ledger fingerprinted it and made every
  // honest retry 409 in production.
  assert.equal(
    requestFingerprint({ ...base, correlationId: 'a', requestId: 'x', idempotencyKey: 'k1' }),
    requestFingerprint({ ...base, correlationId: 'b', requestId: 'y', idempotencyKey: 'k2' }),
  )
  // And a genuinely different request still fingerprints differently.
  assert.notEqual(requestFingerprint(base), requestFingerprint({ ...base, subjectId: 'e-2' }))
})

test('the fingerprint sorts keys, so serialisation order does not 409 a retry', () => {
  assert.equal(
    requestFingerprint({ b: 1, a: { d: 2, c: 3 } }),
    requestFingerprint({ a: { c: 3, d: 2 }, b: 1 }),
  )
})

test('THE KEY IS NAMESPACED BY THE OPERATOR, not by the service', () => {
  // Two operators independently choosing `remediate-2026-08-01` must not collide. Here a collision
  // would replay one operator's request as the answer to another's, and the audit would show the
  // wrong name — which is why the namespace differs from every other service in the estate.
  assert.notEqual(
    namespacedKey(OPERATOR_ONE, '/v1/approvals', 'k'),
    namespacedKey(OPERATOR_TWO, '/v1/approvals', 'k'),
  )
  // And the route is in it, because one key presented to two routes describes two operations.
  assert.notEqual(
    namespacedKey(OPERATOR_ONE, '/v1/approvals', 'k'),
    namespacedKey(OPERATOR_ONE, '/v1/broadcasts', 'k'),
  )
})

test('a retry replays the stored response and does the work once', { skip }, async () => {
  let runs = 0
  const run = () =>
    withIdempotency(db(sql!), {
      principal: OPERATOR_ONE,
      route: '/v1/approvals',
      clientKey: 'k1',
      requestHash: requestFingerprint({ a: 1 }),
      run: async () => {
        runs += 1
        return { response: { id: `made-${runs}` }, artefactId: `made-${runs}` }
      },
    })
  const first = await run()
  const second = await run()
  assert.equal(first.replayed, false)
  assert.equal(second.replayed, true)
  assert.deepEqual(second.result, first.result)
  assert.equal(runs, 1)
})

test('a reused key with a different body is refused, never replayed', { skip }, async () => {
  // Returning the first request's answer to a second, different request is worse than an error:
  // the caller believes the thing it asked for happened.
  await withIdempotency(db(sql!), {
    principal: OPERATOR_ONE,
    route: '/v1/approvals',
    clientKey: 'k1',
    requestHash: requestFingerprint({ a: 1 }),
    run: async () => ({ response: { id: 'x' }, artefactId: 'x' }),
  })
  await assert.rejects(
    async () =>
      withIdempotency(db(sql!), {
        principal: OPERATOR_ONE,
        route: '/v1/approvals',
        clientKey: 'k1',
        requestHash: requestFingerprint({ a: 2 }),
        run: async () => ({ response: { id: 'y' }, artefactId: 'y' }),
      }),
    IdempotencyKeyReuseError,
  )
})

test('a claim with no response yet reads as in-flight, not as done', { skip }, async () => {
  // If the original transaction rolled back between the insert and this read, nothing committed,
  // so the honest answer is "retry" rather than a guess.
  const key = namespacedKey(OPERATOR_ONE, '/v1/approvals', 'k1')
  await sql!`insert into idempotency_keys (key, route, request_hash)
             values (${key}, '/v1/approvals', ${requestFingerprint({ a: 1 })})`
  await assert.rejects(
    async () =>
      withIdempotency(db(sql!), {
        principal: OPERATOR_ONE,
        route: '/v1/approvals',
        clientKey: 'k1',
        requestHash: requestFingerprint({ a: 1 }),
        run: async () => ({ response: { id: 'x' }, artefactId: 'x' }),
      }),
    IdempotencyInFlightError,
  )
})

test('A CONCURRENT DUPLICATE BLOCKS AND THEN REPLAYS — it does not race', { skip }, async () => {
  let runs = 0
  const run = () =>
    withIdempotency(db(sql!), {
      principal: OPERATOR_ONE,
      route: '/v1/approvals',
      clientKey: 'concurrent',
      requestHash: requestFingerprint({ a: 1 }),
      run: async (tx) => {
        runs += 1
        // Hold the transaction open, so the second attempt genuinely overlaps the first.
        await tx`select pg_sleep(0.15)`
        return { response: { id: `made-${runs}` }, artefactId: `made-${runs}` }
      },
    })
  const [first, second] = await Promise.all([run(), run()])
  assert.equal(runs, 1, 'a double-clicked button must not raise two requests')
  assert.deepEqual(first.result, second.result)
  assert.equal([first.replayed, second.replayed].filter(Boolean).length, 1)
})

test('the reaper is bounded and keeps productive claims', { skip }, async () => {
  const old = new Date(Date.now() - 40 * 24 * 60 * 60_000).toISOString()
  for (let i = 0; i < 5; i++) {
    await sql!`insert into idempotency_keys (key, route, request_hash, created_at)
               values (${`spent-${i}`}, '/v1/approvals', 'h', ${old}::timestamptz)`
  }
  await sql!`insert into idempotency_keys (key, route, request_hash, artefact_id, created_at)
             values ('kept', '/v1/approvals', 'h', 'approval-1', ${old}::timestamptz)`
  assert.equal(await reapIdempotencyKeys(db(sql!), 14), 5)
  assert.deepEqual((await sql!<{ key: string }[]>`select key from idempotency_keys`).map((r) => r.key), ['kept'])
})

test('the reaper keeps everything inside the TTL', { skip }, async () => {
  // Expiring a key EARLY means the next replay of it raises a second approval request.
  await sql!`insert into idempotency_keys (key, route, request_hash) values ('fresh', '/v1/approvals', 'h')`
  assert.equal(await reapIdempotencyKeys(db(sql!), 14), 0)
})
