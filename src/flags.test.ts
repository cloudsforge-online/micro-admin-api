/**
 * Feature flags and broadcasts.
 *
 * Both are in SD-15's Admin row — "every operator action, feature flag change, broadcast" — so
 * every write here is checked for its audit row as well as for its effect, and for the outbox
 * event that tells the service behind the flag that something changed. A flag this service knows
 * about and the service behind it does not is a flag that does nothing.
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { FlagError, findFlag, listFlags, setFlag } from './flags.ts'
import {
  BroadcastError,
  BroadcastNotFoundError,
  SEVERITIES,
  listBroadcasts,
  publishBroadcast,
  retractBroadcast,
} from './broadcasts.ts'
import { verifyChain } from './audit.ts'
import { OPERATOR_ONE, OPERATOR_TWO, enabled, migrateTestDb, openDb, resetAdminApi, skip } from './testsupport.ts'

const sql = enabled ? openDb() : null
const PRODUCER = 'admin-api'

before(async () => {
  if (sql) await migrateTestDb(sql)
})
beforeEach(async () => {
  if (sql) await resetAdminApi(sql)
})
after(async () => {
  if (sql) await sql.end({ timeout: 5 })
})

async function put(overrides: Record<string, unknown> = {}) {
  const out = await sql!.begin(async (tx) => ({
    value: await setFlag(
      tx,
      {
        key: 'market.listing_enabled',
        enabled: true,
        description: 'Marketplace listing creation',
        owner: 'platform-team',
        operator: OPERATOR_ONE,
        ...overrides,
      } as Parameters<typeof setFlag>[1],
      PRODUCER,
    ),
  }))
  return out.value
}

/* ------------------------------------------------------------------ flags */

test('a flag is created with its owner and its stated default', { skip }, async () => {
  const { flag, changed } = await put({ enabled: false })
  assert.equal(flag.enabled, false)
  assert.equal(flag.owner, 'platform-team')
  assert.equal(flag.updatedBy, OPERATOR_ONE)
  assert.equal(changed, true, 'a new flag is a change')
})

test('a flag with no owner is refused, and nothing is written', { skip }, async () => {
  await assert.rejects(async () => put({ owner: '  ' }), FlagError)
  assert.equal((await listFlags(sql!)).length, 0)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('a flag with no description is refused', { skip }, async () => {
  // 17 §1 row 8 requires the default to be STATED. A flag whose description is empty is a flag
  // nobody can decide about six months later.
  await assert.rejects(async () => put({ description: '' }), FlagError)
})

test('the audit row records the value before AND after', { skip }, async () => {
  await put({ enabled: false })
  await put({ enabled: true, operator: OPERATOR_TWO })

  const rows = await sql!<{ action: string; actor: string; payload: any }[]>`
    select action, actor, payload from audit_events order by seq
  `
  assert.deepEqual(rows.map((r) => r.action), ['admin.flag.created', 'admin.flag.changed'])
  assert.equal(rows[0]?.payload.before, null)
  assert.equal(rows[0]?.payload.after.enabled, false)
  // "The flag is off" is not the useful fact six months later; "it was on until 03:14 and this
  // operator turned it off" is.
  assert.equal(rows[1]?.payload.before.enabled, false)
  assert.equal(rows[1]?.payload.after.enabled, true)
  assert.equal(rows[1]?.actor, OPERATOR_TWO)
})

test('setting a flag to the value it already has is recorded as unchanged', { skip }, async () => {
  await put({ enabled: true })
  const { changed } = await put({ enabled: true })
  assert.equal(changed, false)
  // Still audited, and still emitted: an owner change is a change somebody downstream may care
  // about, and a consumer deduping on the payload is cheaper than a producer guessing.
  assert.equal((await sql!`select seq from audit_events`).length, 2)
  assert.equal((await sql!`select id from outbox`).length, 2)
})

test('a flag change emits an outbox event IN THE SAME TRANSACTION', { skip }, async () => {
  await assert.rejects(async () =>
    sql!.begin(async (tx) => {
      await setFlag(
        tx,
        {
          key: 'market.listing_enabled',
          enabled: true,
          description: 'd',
          owner: 'platform',
          operator: OPERATOR_ONE,
        },
        PRODUCER,
      )
      throw new Error('the rest of the operation failed')
    }),
  )
  // A publish before commit announces something that never happened.
  assert.equal((await sql!`select id from outbox`).length, 0)
  assert.equal((await listFlags(sql!)).length, 0)
  assert.equal((await sql!`select seq from audit_events`).length, 0)
})

test('an owner change is audited even when the boolean does not move', { skip }, async () => {
  await put({ enabled: true, owner: 'platform-team' })
  await put({ enabled: true, owner: 'wallet-team', operator: OPERATOR_TWO })
  const flag = await findFlag(sql!, 'market.listing_enabled')
  assert.equal(flag?.owner, 'wallet-team')
  const rows = await sql!<{ payload: any }[]>`select payload from audit_events order by seq desc limit 1`
  assert.equal(rows[0]?.payload.before.owner, 'platform-team')
  assert.equal(rows[0]?.payload.after.owner, 'wallet-team')
})

test('flags list in key order, and an unknown flag reads as null', { skip }, async () => {
  await put({ key: 'zeta.flag' })
  await put({ key: 'alpha.flag' })
  assert.deepEqual((await listFlags(sql!)).map((f) => f.key), ['alpha.flag', 'zeta.flag'])
  assert.equal(await findFlag(sql!, 'no.such.flag'), null)
})

/* ------------------------------------------------------------------ broadcasts */

async function publish(overrides: Record<string, unknown> = {}) {
  const out = await sql!.begin(async (tx) => ({
    value: await publishBroadcast(
      tx,
      {
        severity: 'maintenance',
        title: 'Ledger maintenance',
        body: 'Withdrawals pause for twenty minutes.',
        operator: OPERATOR_ONE,
        ...overrides,
      } as Parameters<typeof publishBroadcast>[1],
      PRODUCER,
    ),
  }))
  return out.value
}

test('a broadcast is published, audited and announced', { skip }, async () => {
  const { broadcast } = await publish()
  assert.equal(broadcast.severity, 'maintenance')
  assert.equal(broadcast.publishedBy, OPERATOR_ONE)
  assert.equal(broadcast.retractedAt, null)

  const audit = await sql!<{ action: string; actor: string }[]>`select action, actor from audit_events`
  assert.equal(audit[0]?.action, 'admin.broadcast.published')
  assert.equal(audit[0]?.actor, OPERATOR_ONE)
  const events = await sql!<{ topic: string }[]>`select topic from outbox`
  assert.equal(events[0]?.topic, 'admin.broadcast.published')
})

test('every severity in the closed list is accepted, and nothing else is', { skip }, async () => {
  for (const severity of SEVERITIES) await publish({ severity })
  assert.equal((await listBroadcasts(sql!)).length, SEVERITIES.length)
  await assert.rejects(async () => publish({ severity: 'catastrophe' }), BroadcastError)
})

test('a window that ends before it starts is refused', { skip }, async () => {
  await assert.rejects(
    async () =>
      publish({ startsAt: new Date('2026-08-01T10:00:00Z'), endsAt: new Date('2026-08-01T09:00:00Z') }),
    /endsAt must be after startsAt/,
  )
})

test('RETRACTED, NOT DELETED', { skip }, async () => {
  const { broadcast } = await publish()
  const { broadcast: retracted } = await sql!
    .begin(async (tx) => ({ value: await retractBroadcast(tx, broadcast.id, OPERATOR_TWO, 'req-1', PRODUCER) }))
    .then((o) => o.value)
    .then((v) => ({ broadcast: v.broadcast }))

  assert.equal(retracted.retractedBy, OPERATOR_TWO)
  // "What did we tell users during the incident, and when did we stop saying it" is a question
  // asked during the post-incident review. A DELETE makes it unanswerable.
  assert.equal((await listBroadcasts(sql!)).length, 1)
  assert.equal((await listBroadcasts(sql!, { liveAt: new Date() })).length, 0)
})

test('a second retraction is refused rather than audited twice', { skip }, async () => {
  const { broadcast } = await publish()
  await sql!.begin(async (tx) => ({ value: await retractBroadcast(tx, broadcast.id, OPERATOR_TWO, null, PRODUCER) }))
  await assert.rejects(
    async () =>
      sql!.begin(async (tx) => ({ value: await retractBroadcast(tx, broadcast.id, OPERATOR_TWO, null, PRODUCER) })),
    /already retracted/,
  )
  assert.equal((await sql!`select seq from audit_events where action = 'admin.broadcast.retracted'`).length, 1)
})

test('retracting something that does not exist is a not-found', { skip }, async () => {
  await assert.rejects(
    async () =>
      sql!.begin(async (tx) => ({
        value: await retractBroadcast(tx, '99999999-9999-4999-8999-999999999999', OPERATOR_ONE, null, PRODUCER),
      })),
    BroadcastNotFoundError,
  )
})

test('the live filter honours the window in both directions', { skip }, async () => {
  const now = new Date('2026-08-01T12:00:00Z')
  await publish({ title: 'past', startsAt: new Date('2026-08-01T08:00:00Z'), endsAt: new Date('2026-08-01T09:00:00Z') })
  await publish({ title: 'future', startsAt: new Date('2026-08-01T18:00:00Z') })
  await publish({ title: 'now', startsAt: new Date('2026-08-01T11:00:00Z'), endsAt: new Date('2026-08-01T13:00:00Z') })
  await publish({ title: 'open-ended', startsAt: new Date('2026-08-01T11:00:00Z') })

  const live = await listBroadcasts(sql!, { liveAt: now })
  assert.deepEqual(live.map((b) => b.title).sort(), ['now', 'open-ended'])
})

test('THIS SERVICE HOLDS NO ADDRESSEE — a broadcast is not a notification', { skip }, async () => {
  // A notification is an addressed message with a read state that notify owns, and 17 §7 row 8
  // requires a `critical` security notification to be delivered DESPITE preferences. That decision
  // belongs to the service that knows who the message is for. This one does not, and must not.
  const columns = await sql!<{ column_name: string }[]>`
    select column_name from information_schema.columns where table_name = 'broadcasts'
  `
  const names = columns.map((c) => c.column_name)
  for (const forbidden of ['user_id', 'read_at', 'recipient', 'channel', 'preference']) {
    assert.ok(!names.includes(forbidden), `broadcasts.${forbidden} would make this a notify service`)
  }
})

test('flags and broadcasts together leave one verifiable chain', { skip }, async () => {
  await put()
  const { broadcast } = await publish()
  await sql!.begin(async (tx) => ({ value: await retractBroadcast(tx, broadcast.id, OPERATOR_TWO, null, PRODUCER) }))
  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, true)
  assert.equal(result.totalEvents, 3)
})
