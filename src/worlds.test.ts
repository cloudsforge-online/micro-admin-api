/**
 * The Forge Worlds routes — the admin path that takes *Ninety Days After* out of `draft`.
 *
 * These are a proxy onto `nda`, and a proxy's tests are about the things a proxy gets wrong:
 *
 *   1. **WHICH BEARER GOES UPSTREAM.** `nda`'s `requireAdminPrincipal` admits either a service
 *      holding `nda:write` or a user with `role:admin`, so a regression to this service's own token
 *      would still return 200 — and would relabel every world in the game as having been generated
 *      by `service:admin-api`. The fake records every bearer and the tests read it back, the same
 *      assertion `mail.test.ts` carries for notify.
 *
 *   2. **THAT AN `Idempotency-Key` IS DEMANDED RATHER THAN INVENTED.** Creating a world builds a
 *      whole map. A double-submitted form without a key builds two worlds, and neither of them is
 *      wrong enough for anything downstream to notice. Defaulting the key to this request's id
 *      would satisfy nda's header policy and defeat its purpose, so the absence is a 400 here.
 *
 *   3. **THAT AN AUDIT ROW IS WRITTEN.** nda records its own outbox events, but this console's
 *      hash-chained log is where "who generated that world" is asked, and it is a separate write
 *      that a proxy is free to forget.
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

const WORLD = '11111111-2222-4333-8444-555555555555'

async function harnessFor(): Promise<Harness> {
  if (sql) await resetAdminApi(sql)
  return startHarness(sql!, fakeVerifier({ 'operator-bearer': operatorPrincipal(ALICE) }), {})
}

test("the operator's OWN bearer reaches nda on every world call", { skip }, async () => {
  const harness = await harnessFor()
  try {
    await harness.request('GET', '/v1/worlds', { token: 'operator-bearer' })
    await harness.request('POST', '/v1/worlds', {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { name: 'The long winter' },
    })
    await harness.request('POST', `/v1/worlds/${WORLD}/start`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })
    await harness.request('POST', `/v1/worlds/${WORLD}/tick`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })
    await harness.request('PUT', `/v1/worlds/${WORLD}/bots`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { enabled: true, count: 12 },
    })

    assert.deepEqual(
      harness.nda.calls.map((c) => c.method),
      ['list', 'create', 'start', 'tick', 'bots'],
    )
    // The whole point: not one of these may carry a service token.
    assert.deepEqual(
      [...new Set(harness.nda.calls.map((c) => c.bearer))],
      ['operator-bearer'],
      "every nda call must carry the operator's own bearer",
    )
  } finally {
    await harness.close()
  }
})

test('a world is generated, and 201 says it is new', { skip }, async () => {
  const harness = await harnessFor()
  try {
    const res = await harness.request('POST', '/v1/worlds', {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { name: 'The long winter', width: 32, seed: 'winter-1' },
    })
    assert.equal(res.status, 201)
    const body = res.body as { world: { name: string; width: number; seed: string } }
    assert.equal(body.world.name, 'The long winter')
    // Forwarded rather than dropped: nda bounds width to 12..64 and takes its own default when the
    // field is absent, so a proxy that swallowed it would silently generate 24 every time.
    assert.equal(body.world.width, 32)
    assert.equal(body.world.seed, 'winter-1')
  } finally {
    await harness.close()
  }
})

test('creating a world without an Idempotency-Key is refused, and nda is never called', { skip }, async () => {
  const harness = await harnessFor()
  try {
    const res = await harness.request('POST', '/v1/worlds', {
      token: 'operator-bearer',
      body: { name: 'The long winter' },
    })
    assert.equal(res.status, 400)
    // Refused HERE. Reaching nda and being refused there would be the same status and a world's
    // worth of map generation away from it.
    assert.deepEqual(harness.nda.calls, [], 'nda must not be called at all')
  } finally {
    await harness.close()
  }
})

test('a tick answers 202 — it is queued, not resolved', { skip }, async () => {
  const harness = await harnessFor()
  try {
    const res = await harness.request('POST', `/v1/worlds/${WORLD}/tick`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })
    // 202 matching nda's own answer. A 200 would tell an operator the day had resolved when the
    // job is still behind the world's lease, and they would stop watching.
    assert.equal(res.status, 202)
    assert.equal((res.body as { queued: boolean }).queued, true)
  } finally {
    await harness.close()
  }
})

test('bots off syncs to zero regardless of the count sent', { skip }, async () => {
  const harness = await harnessFor()
  try {
    const res = await harness.request('PUT', `/v1/worlds/${WORLD}/bots`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { enabled: false, count: 40 },
    })
    assert.equal(res.status, 200)
    assert.equal((res.body as { bots: number }).bots, 0)
  } finally {
    await harness.close()
  }
})

test('a malformed world id is refused before nda is dialled', { skip }, async () => {
  const harness = await harnessFor()
  try {
    const res = await harness.request(`POST`, `/v1/worlds/${'x'.repeat(200)}/start`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })
    assert.equal(res.status, 400)
    assert.deepEqual(harness.nda.calls, [])
  } finally {
    await harness.close()
  }
})

/**
 * The gate above used to demand a uuid, and the live estate proved that wrong.
 *
 * `nda.worlds.id` is `text`, and the mainnet database holds `drill-world` — seeded 2026-08-05,
 * before there was a create route to mint a uuid. It is in `lobby`, so the console lists it with
 * an "Open for play" button, and a uuid gate made that button answer 400 forever. A world that
 * exists must be actionable; whether it exists is nda's question, not this service's.
 */
test('a world whose id is not a uuid is still actionable, because nda stores ids as text', { skip }, async () => {
  const harness = await harnessFor()
  try {
    const res = await harness.request('POST', '/v1/worlds/drill-world/start', {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })
    assert.equal(res.status, 200)
    assert.deepEqual(
      harness.nda.calls.map((c) => [c.method, c.worldId]),
      [['start', 'drill-world']],
    )
  } finally {
    await harness.close()
  }
})

test('every world mutation writes an audit row naming the operator', { skip }, async () => {
  const harness = await harnessFor()
  try {
    await harness.request('POST', '/v1/worlds', {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { name: 'The long winter', seed: 'winter-1' },
    })
    await harness.request('POST', `/v1/worlds/${WORLD}/start`, {
      token: 'operator-bearer',
      headers: { 'idempotency-key': freshKey() },
    })

    const rows = await sql!<{ action: string; actor: string; payload: Record<string, unknown> }[]>`
      select action, actor, payload from audit_events
       where subject_kind = 'world' order by seq`
    assert.deepEqual(
      rows.map((r) => r.action),
      ['admin.world.created', 'admin.world.started'],
    )
    assert.deepEqual([...new Set(rows.map((r) => r.actor))], [`user:${ALICE}`])
    // The seed is what makes a world reproducible — same seed, same inputs, byte-identical
    // resolution — so the row that records a world's creation has to carry it.
    assert.equal(rows[0]?.payload['seed'], 'winter-1')
  } finally {
    await harness.close()
  }
})

test('a read-scoped SERVICE token may list worlds, but may not generate one', { skip }, async () => {
  if (sql) await resetAdminApi(sql)
  const verifier = fakeVerifier({
    'service-bearer': servicePrincipal('estate-dashboard', ['admin:read']),
  })
  const harness: Harness = await startHarness(sql!, verifier, {})
  try {
    // Reading is `requireReader`: asking what worlds exist should not need the authority to build
    // one.
    const list = await harness.request('GET', '/v1/worlds', { token: 'service-bearer' })
    assert.equal(list.status, 200)

    // Generating a world runs the map generator and creates a season people will play. That is an
    // operator's act, and `requireOperator` refuses a service principal outright.
    const create = await harness.request('POST', '/v1/worlds', {
      token: 'service-bearer',
      headers: { 'idempotency-key': freshKey() },
      body: { name: 'The long winter' },
    })
    assert.equal(create.status, 403)
    assert.deepEqual(
      harness.nda.calls.map((c) => c.method),
      ['list'],
      'the refused create must not have reached nda',
    )
  } finally {
    await harness.close()
  }
})
