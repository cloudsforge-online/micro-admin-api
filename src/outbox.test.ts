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
  DELIVERY_TOLERANCE_MS,
  EVENT_ID_HEADER,
  classifyEnvelope,
  signDelivery,
  verifyDelivery,
  type EventVersion,
} from '@cloudsforge/contracts-events'
import {
  EVENT_ID_HEADER as EXPORTED_EVENT_ID_HEADER,
  SIGNATURE_HEADER as EXPORTED_SIGNATURE_HEADER,
  buildEnvelope,
  createRelay,
  emitOn,
  withInbox,
  type Db,
  type OutboxRow,
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

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THIS SERVICE SPEAKS THE ESTATE'S SIGNING SCHEME, NOT ONE OF ITS OWN.
//
// It used to hand-roll `x-cloudsforge-signature: sha256=<hmac(body)>`. Every producer and every
// inbox in the estate speaks `cf-signature: t=<s>,v1=<hmac("<s>.<body>")>`. The two agree on
// neither the header name nor the value format, so this service's mirror refused every real
// delivery and this service's own events were refused by every real subscriber.
//
// These first two cases are the ones that fail against the previous build: they assert the wire
// CONSTANTS, which is the half a signing test normally forgets — the old scheme's MAC comparison
// was perfectly correct and still could not talk to anybody.
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('THE SIGNATURE HEADER IS THE ESTATE CONSTANT, not a local spelling', () => {
  assert.equal(EXPORTED_SIGNATURE_HEADER, 'cf-signature')
  assert.notEqual(EXPORTED_SIGNATURE_HEADER, 'x-cloudsforge-signature')
})

test('THE EVENT ID HEADER IS THE ESTATE CONSTANT, not the hard-coded `x-event-id`', () => {
  assert.equal(EXPORTED_EVENT_ID_HEADER, 'cf-event-id')
})

test('a signature verifies over the exact bytes and nothing else', () => {
  const body = JSON.stringify({ topic: 'admin.flag.changed', key: 'a' })
  const signature = signDelivery(body, SECRET)
  assert.equal(verifyDelivery(body, signature, SECRET).ok, true)
  // One trailing space. A verifier working from a re-serialisation would not notice.
  assert.equal(verifyDelivery(`${body} `, signature, SECRET).ok, false)
  assert.equal(verifyDelivery(body, signature, 'another-secret-of-sufficient-length').ok, false)
})

test('THE SCHEME HAS A REPLAY WINDOW, which the hand-rolled one did not', () => {
  // The property actually gained by the change, and the reason it is not merely a rename. The old
  // `sha256=<hmac(body)>` carried no timestamp, so a captured POST to the audit intake stayed
  // valid for ever — on the one record a dispute is settled against.
  const body = '{"a":1}'
  const signedAt = 1_800_000_000_000
  const signature = signDelivery(body, SECRET, signedAt)
  assert.equal(verifyDelivery(body, signature, SECRET, { now: signedAt }).ok, true)
  const stale = verifyDelivery(body, signature, SECRET, { now: signedAt + DELIVERY_TOLERANCE_MS + 1_000 })
  assert.equal(stale.ok, false)
  assert.equal(stale.ok === false && stale.reason, 'stale')
  // And the timestamp is INSIDE the signed message, so it cannot be moved to refresh the window.
  const moved = signature.replace(/^t=\d+/, `t=${Math.floor((signedAt + 60_000) / 1000)}`)
  assert.equal(verifyDelivery(body, moved, SECRET, { now: signedAt + 60_000 }).ok, false)
})

test('a malformed or empty signature header is refused', () => {
  assert.equal(verifyDelivery('{}', 'sha256=deadbeef', SECRET).ok, false)
  assert.equal(verifyDelivery('{}', '', SECRET).ok, false)
})

test('rotation is a window: a superseded secret still verifies, and says so', () => {
  const body = '{"a":1}'
  const old = 'the-previous-secret-of-sufficient-length'
  const signature = signDelivery(body, old)
  const verified = verifyDelivery(body, signature, [SECRET, old])
  assert.equal(verified.ok, true)
  assert.equal(verified.ok === true && verified.keyIndex, 1, 'a non-zero index is what flags an unfinished rotation')
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

  // ── THE HEADERS A REAL SUBSCRIBER READS, asserted by the estate's own constants rather than by
  // strings copied from this file's implementation. Against the previous build the signature
  // arrived under `x-cloudsforge-signature` and the id under `x-event-id`, so every inbox in the
  // estate — all of which read `cf-signature` — saw an unsigned request and answered 401.
  const signature = seen[0]!.headers[EXPORTED_SIGNATURE_HEADER]
  assert.ok(signature, `the relay must send ${EXPORTED_SIGNATURE_HEADER}`)
  // The id header is compared against the row in the database — an independent fact — rather than
  // against the header itself, which would assert nothing.
  const [row] = await sql!<{ id: string }[]>`select id from outbox`
  assert.equal(seen[0]!.headers[EVENT_ID_HEADER], row!.id)

  // ── AND IT IS VERIFIED FROM THE RECEIVING END, with the same function a subscriber calls, over
  // the body the client actually received. This is what closes the serialisation coupling noted
  // in `outbox.ts`: if `HttpClient` ever stringifies differently from the relay, this goes red.
  assert.match(signature, /^t=\d+,v1=[0-9a-f]+$/, 'the estate scheme, not a local one')
  assert.equal(verifyDelivery(JSON.stringify(seen[0]!.body), signature, SECRET).ok, true)

  // ── AND WHAT IS INSIDE THOSE BYTES. The signature above was right for months while the envelope
  // was not, so verifying the delivery proves only that the wrapper is intact.
  //
  // MUTATION THIS KILLS, confirmed red: `createRelay` assembling an envelope literal of its own
  // again instead of calling `buildEnvelope`. The unit tests at the foot of this file cannot see
  // that one — they call `buildEnvelope` directly — so it is asserted here, on the body the fake
  // client actually received, which is the only statement about what a subscriber gets.
  const body = seen[0]!.body as Record<string, unknown>
  assert.equal(body['version'], '1.0', 'the contract"s "major.minor", never the stored integer')
  assert.equal(classifyEnvelope(body).defects.length, 0, `${JSON.stringify(classifyEnvelope(body))}`)

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
  // replay request — but it is NOT what the comment inherited from market/src/outbox.ts
  // claims — nor what service-template/src/outbox.ts claims, which is where market got it and
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

/* ------------------------------------------------------------------ what goes on the wire */

/**
 * An INVENTED row, and it says so — micro-org#366.
 *
 * Measured on the mainnet estate on 2026-08-11: this service's outbox is empty, so there is no
 * real row to read. `admin.flag.changed` is a real emit site (`flags.ts`) and its shape is the
 * shape a flag change will have; none of this service's three topics is registered yet, so this
 * is the latent half of the defect — it typechecks, it is green, and it surfaces on the day the
 * topics are registered, which is the day nobody is looking for it.
 */
const STORED_ROW: OutboxRow = {
  id: '4c1a9f7e-5d38-4b21-8e0c-7a2f9d6b3c15',
  topic: 'admin.flag.changed',
  key: 'faucet-enabled',
  occurred_at: new Date('2026-08-11T00:00:00.000Z'),
  producer: 'admin-api',
  version: 1,
  actor: null,
  correlation_id: null,
  payload: { flag: 'faucet-enabled', value: true },
}

/**
 * **THE SIGNATURE WAS RIGHT AND THE ENVELOPE WAS NOT.**
 *
 * `@cloudsforge/contracts-events` types the wire version as "major.minor" — a STRING — and this
 * relay stamped the stored INTEGER. A delivery that verified was still discarded at the envelope
 * before any consumer read a payload. Eight relays did this at once and every suite in the estate
 * stayed green, because each one declared its OWN `EventEnvelope` and no compiler ever compared
 * the two.
 *
 * Measured with the contract's own `classifyEnvelope` against `STORED_ROW` on 2026-08-11:
 *
 *      as shipped -> malformed: version: missing, actor: missing, correlationId: missing
 *     fixed      -> well-formed; only the registration is outstanding
 *
 * The verdict is taken from the CONTRACT'S OWN classifier, never from a shape restated here. A
 * local copy of the rule agrees with a wrong implementation instead of catching it, which is the
 * mistake that produced the defect in the first place.
 *
 * MUTATIONS THIS KILLS — each one applied to `buildEnvelope` and each one confirmed red:
 *   - `version: row.version`, the stored integer, which is what shipped: `classifyEnvelope`
 *     answers `version: missing` and the defect assertion fails.
 *   - `version: String(row.version)` — a string, but "1" rather than "1.0": the shape assertion
 *     fails, so widening the fix to "any string" does not survive either.
 *   - `actor: row.actor` / `correlationId: row.correlation_id`, the nullable columns passed
 *     straight through, which is the other half of what the estate measured above.
 */
test('the envelope this relay puts on the wire is one the contract accepts', () => {
  const envelope = buildEnvelope(STORED_ROW)

  assert.equal(typeof envelope.version, 'string', 'an integer version is refused as "version: missing"')
  assert.match(envelope.version, /^\d+\.\d+$/, 'the contract types the wire version as "major.minor"')
  assert.equal(envelope.version, '1.0', 'major 1 as stored, minor 0 — storage records the major')
  // The nullable columns never reach the wire. `system` is the contract's own value for "no
  // principal did this"; the correlation id falls back to the event id so it is never absent.
  // This row has actor and correlationId null in storage, which is two of the defects measured above.
  assert.equal(envelope.actor, 'system')
  assert.equal(envelope.correlationId, STORED_ROW.id)

  // The topic is not in the contract's registry yet, so the honest verdict is `unregistered_topic`
  // and NOT `valid` — a different fact with a different remedy. What matters here is `defects`:
  // once the registration lands, an EMPTY defect list is the difference between this event being
  // read and being discarded, and `version: missing` is what used to be in it.
  const verdict = classifyEnvelope(envelope)
  assert.equal(verdict.reason, 'unregistered_topic', `got: ${JSON.stringify(verdict)}`)
  assert.deepEqual(verdict.defects, [], 'well-formed: the ONLY thing outstanding is the registration')
})

/**
 * The teeth of the test above. Without this, every assertion there would still pass against a
 * classifier that accepted anything at all, and "the contract accepts it" would be a claim about
 * this file rather than about the estate.
 */
test('the shape this relay used to send is REFUSED by the same classifier', () => {
  const asShipped = { ...buildEnvelope(STORED_ROW), version: STORED_ROW.version as unknown as EventVersion }

  const verdict = classifyEnvelope(asShipped)
  assert.equal(verdict.ok, false, 'an integer version must be refused at the envelope')
  assert.equal(verdict.reason, 'malformed', 'refused as malformed, not merely shelved as unregistered')
  assert.ok(
    verdict.defects.some((d) => d.startsWith('version')),
    `refused FOR THE VERSION, not incidentally: ${JSON.stringify(verdict)}`,
  )
})
