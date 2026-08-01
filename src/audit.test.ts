/**
 * The audit chain.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE EXIT CRITERION OF THIS REPOSITORY IS IN THIS FILE: TAMPERING IS DETECTED.**
 *
 * Four tampers are performed against a real Postgres — an edited field, a deleted interior row, a
 * truncated tail, and a re-hashed forgery — and each is asserted to be caught, by the specific
 * break kind, at the specific sequence. And in the other direction: an untouched chain verifies,
 * a chain that has legitimately grown verifies, and the verifier does not report a break on a row
 * nobody touched. A detector that fires on everything detects nothing.
 *
 * The re-hash case is the honest one: an attacker who edits a row AND recomputes every hash after
 * it produces a chain that verifies. It is asserted to verify, and asserted to be caught by the
 * CHECKPOINT — which is the only defence against it and the reason checkpoints exist.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  GENESIS_HASH,
  appendAudit,
  canonicalJson,
  canonicalRow,
  chainHead,
  hashRow,
  readAudit,
  verifyChain,
  writeCheckpoint,
  DuplicateMirrorError,
  type AuditInput,
  type HashableAuditRow,
} from './audit.ts'
import { OPERATOR_ONE, OPERATOR_TWO, enabled, migrateTestDb, openDb, resetAdminApi, skip } from './testsupport.ts'

/** A break list an assertion message can print. `seq` is a bigint, which JSON.stringify refuses. */
function shown(result: { breaks: ReadonlyArray<{ kind: string; seq: bigint; detail: string }> }): string {
  return JSON.stringify(result.breaks.map((b) => ({ ...b, seq: b.seq.toString() })))
}

/* ------------------------------------------------------------------ pure, no database */

const SAMPLE: HashableAuditRow = {
  seq: 7n,
  id: '11111111-1111-4111-8111-111111111111',
  occurredAt: '2026-08-01T00:00:00.000Z',
  recordedAt: '2026-08-01T00:00:01.000Z',
  actor: OPERATOR_ONE,
  action: 'admin.approval.granted',
  subjectKind: 'approval',
  subjectId: 'abc',
  reasonCode: 'incident_remediation',
  outcome: 'allowed',
  source: 'admin-api',
  sourceEventId: null,
  correlationId: 'req-1',
  payload: { a: 1, b: [2, 3] },
}

test('the hash changes when any hashed field changes', () => {
  const base = hashRow(GENESIS_HASH, SAMPLE)
  const fields: Array<Partial<HashableAuditRow>> = [
    { seq: 8n },
    { id: '22222222-2222-4222-8222-222222222222' },
    { occurredAt: '2026-08-01T00:00:00.001Z' },
    { recordedAt: '2026-08-01T00:00:02.000Z' },
    { actor: OPERATOR_TWO },
    { action: 'admin.approval.rejected' },
    { subjectKind: 'ledger_entry' },
    { subjectId: 'abd' },
    { reasonCode: 'fraud_response' },
    { outcome: 'refused' },
    { source: 'ledger' },
    { sourceEventId: '33333333-3333-4333-8333-333333333333' },
    { correlationId: 'req-2' },
    { payload: { a: 2, b: [2, 3] } },
  ]
  for (const change of fields) {
    const [name] = Object.keys(change)
    assert.notEqual(hashRow(GENESIS_HASH, { ...SAMPLE, ...change }), base, `changing ${name} did not change the hash`)
  }
  // Fourteen fields, and the row has fourteen hashed fields. A field added to the row without a
  // line here would be a field somebody could change without leaving a mark.
  assert.equal(fields.length, Object.keys(SAMPLE).length)
})

test('the hash changes when the predecessor changes', () => {
  assert.notEqual(hashRow(GENESIS_HASH, SAMPLE), hashRow('something-else', SAMPLE))
})

test('fields are length-prefixed, so a shift between two of them is not invisible', () => {
  // Without framing, actor='ab' + action='c' and actor='a' + action='bc' serialise identically and
  // two genuinely different rows share a hash. This is the classic way a MAC over structured data
  // stops meaning anything.
  const left = hashRow(GENESIS_HASH, { ...SAMPLE, actor: 'user:ab', action: 'c' })
  const right = hashRow(GENESIS_HASH, { ...SAMPLE, actor: 'user:a', action: 'bc' })
  assert.notEqual(left, right)
})

test('a null field cannot be forged by a caller writing the literal', () => {
  // `reasonCode: null` renders as ' null' with a leading space, which no JSON string can produce
  // through this path — so a payload containing the text "null" cannot impersonate an absent one.
  const withNull = canonicalRow({ ...SAMPLE, reasonCode: null })
  const withText = canonicalRow({ ...SAMPLE, reasonCode: 'null' })
  assert.notEqual(withNull, withText)
})

test('canonical JSON sorts keys at every depth', () => {
  assert.equal(
    canonicalJson({ b: 1, a: { d: 2, c: 3 } }),
    canonicalJson({ a: { c: 3, d: 2 }, b: 1 }),
  )
})

test('canonical JSON is stable across the jsonb round trip that reorders keys', () => {
  // Postgres `jsonb` does not preserve key order. A verifier re-hashing a row it read back would
  // otherwise report a break on a row nobody touched, which is the failure mode that makes a
  // tamper detector get switched off.
  const written = { zebra: 1, alpha: 2, middle: { z: 1, a: 2 } }
  const readBack = { alpha: 2, middle: { a: 2, z: 1 }, zebra: 1 }
  assert.equal(hashRow(GENESIS_HASH, { ...SAMPLE, payload: written }), hashRow(GENESIS_HASH, { ...SAMPLE, payload: readBack }))
})

/* ------------------------------------------------------------------ against a database */

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

function input(overrides: Partial<AuditInput> = {}): AuditInput {
  return {
    actor: OPERATOR_ONE,
    action: 'admin.flag.changed',
    subjectKind: 'feature_flag',
    subjectId: 'market.listing',
    outcome: 'allowed',
    ...overrides,
  }
}

async function appendMany(count: number): Promise<void> {
  for (let i = 0; i < count; i++) {
    await sql!.begin(async (tx) => {
      await appendAudit(tx, input({ subjectId: `flag-${i}` }))
      return { value: null }
    })
  }
}

test('the first row names the genesis hash', { skip }, async () => {
  const row = await sql!.begin(async (tx) => ({ value: await appendAudit(tx, input()) }))
  assert.equal(row.value.prevHash, GENESIS_HASH)
  assert.equal(row.value.seq, 1n)
})

test('each row commits to its predecessor', { skip }, async () => {
  await appendMany(5)
  const rows = await sql!<{ seq: string; prev_hash: string; hash: string }[]>`
    select seq, prev_hash, hash from audit_events order by seq
  `
  assert.equal(rows.length, 5)
  let previous = GENESIS_HASH
  for (const row of rows) {
    assert.equal(row.prev_hash, previous, `row ${row.seq} does not follow its predecessor`)
    previous = row.hash
  }
})

test('an untouched chain verifies', { skip }, async () => {
  await appendMany(20)
  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, true, shown(result))
  assert.equal(result.checked, 20)
  assert.equal(result.totalEvents, 20)
  assert.deepEqual(result.breaks, [])
})

test('an empty chain verifies, and reports nothing', { skip }, async () => {
  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, true)
  assert.equal(result.totalEvents, 0)
})

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE FOUR TAMPERS.
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('TAMPER: an edited field is detected, at the row it was edited', { skip }, async () => {
  await appendMany(6)
  // The classic: an operator who wants the record to say somebody else did it.
  await sql!`update audit_events set actor = ${OPERATOR_TWO} where seq = 3`

  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, false)
  const mismatch = result.breaks.find((b) => b.kind === 'hash_mismatch')
  assert.ok(mismatch, `expected a hash_mismatch, got ${shown(result)}`)
  assert.equal(mismatch.seq, 3n)
  // And the link after it is intact, because row 4 still names row 3's STORED hash. The edit
  // shows up exactly once, at exactly the row that was edited.
  assert.equal(result.breaks.filter((b) => b.kind === 'link_mismatch').length, 0)
})

test('TAMPER: editing the payload is detected too', { skip }, async () => {
  await appendMany(4)
  await sql!`update audit_events set payload = ${sql!.json({ tampered: true })} where seq = 2`
  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, false)
  assert.equal(result.breaks[0]?.kind, 'hash_mismatch')
  assert.equal(result.breaks[0]?.seq, 2n)
})

test('TAMPER: a deleted interior row is detected, at the gap', { skip }, async () => {
  await appendMany(6)
  const before = await sql!<{ hash: string }[]>`select hash from audit_events where seq = 4`
  await sql!`delete from audit_events where seq = 4`

  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, false)
  const link = result.breaks.find((b) => b.kind === 'link_mismatch')
  assert.ok(link, `expected a link_mismatch, got ${shown(result)}`)
  // Row 5 is the one that no longer follows what precedes it.
  assert.equal(link.seq, 5n)
  assert.ok(link.detail.includes(before[0]!.hash), 'the break should name the hash that is missing')
})

test('TAMPER: a truncated tail is detected — but ONLY against a checkpoint', { skip }, async () => {
  await appendMany(10)
  await writeCheckpoint(sql!, 'service:admin-api@test')

  // Somebody covering their tracks removes the last four rows. This needs no forgery, which is
  // why it is the attack that actually happens.
  await sql!`delete from audit_events where seq > 6`

  const withCheckpoint = await verifyChain(sql!)
  assert.equal(withCheckpoint.ok, false)
  const kinds = withCheckpoint.breaks.map((b) => b.kind).sort()
  assert.deepEqual(kinds, ['checkpoint_missing', 'checkpoint_truncated'])

  // ── AND THE HONEST HALF: without the checkpoint, what remains verifies perfectly. This is the
  // limit of a hash chain, stated as a test rather than as a claim in a comment.
  await sql!`delete from audit_chain_checkpoints`
  const withoutCheckpoint = await verifyChain(sql!, { from: 0n })
  assert.equal(withoutCheckpoint.ok, true, 'a truncated chain is internally consistent — that is the point')
  assert.equal(withoutCheckpoint.totalEvents, 6)
})

test('TAMPER: a re-hashed forgery verifies, and is caught by the checkpoint', { skip }, async () => {
  await appendMany(5)
  const checkpoint = await writeCheckpoint(sql!, 'service:admin-api@test')
  assert.ok(checkpoint)

  // The strongest attacker in the model: edit row 2 and recompute every hash from there forward,
  // so the chain is internally consistent again.
  const rows = await sql!<
    {
      seq: string
      id: string
      occurred_at: Date
      recorded_at: Date
      actor: string
      action: string
      subject_kind: string
      subject_id: string
      reason_code: string | null
      outcome: string
      source: string
      source_event_id: string | null
      correlation_id: string | null
      payload: Record<string, unknown>
    }[]
  >`select seq, id, occurred_at, recorded_at, actor, action, subject_kind, subject_id,
           reason_code, outcome, source, source_event_id, correlation_id, payload
      from audit_events order by seq`

  let previous = GENESIS_HASH
  for (const row of rows) {
    const actor = row.seq === '2' ? OPERATOR_TWO : row.actor
    const hashable: HashableAuditRow = {
      seq: BigInt(row.seq),
      id: row.id,
      occurredAt: row.occurred_at.toISOString(),
      recordedAt: row.recorded_at.toISOString(),
      actor,
      action: row.action,
      subjectKind: row.subject_kind,
      subjectId: row.subject_id,
      reasonCode: row.reason_code,
      outcome: row.outcome,
      source: row.source,
      sourceEventId: row.source_event_id,
      correlationId: row.correlation_id,
      payload: row.payload,
    }
    const hash = hashRow(previous, hashable)
    await sql!`update audit_events set actor = ${actor}, prev_hash = ${previous}, hash = ${hash} where seq = ${row.seq}`
    previous = hash
  }

  // The chain itself is now clean. Nothing stored beside the data it attests can do better.
  const walkOnly = await verifyChain(sql!, { from: 0n })
  assert.equal(walkOnly.breaks.filter((b) => b.kind === 'hash_mismatch' || b.kind === 'link_mismatch').length, 0)

  // ── The checkpoint is what catches it: the head hash it anchored no longer exists.
  const full = await verifyChain(sql!)
  assert.equal(full.ok, false)
  assert.equal(full.breaks[0]?.kind, 'checkpoint_mismatch')
  assert.equal(full.breaks[0]?.seq, checkpoint.seq)
})

test('every break is reported, not just the first', { skip }, async () => {
  await appendMany(8)
  await sql!`update audit_events set actor = ${OPERATOR_TWO} where seq in (2, 5, 7)`
  const result = await verifyChain(sql!, { from: 0n })
  // An operator answering "what was changed" needs the set, not the earliest member of it.
  assert.equal(result.breaks.filter((b) => b.kind === 'hash_mismatch').length, 3)
  assert.deepEqual(result.breaks.map((b) => b.seq), [2n, 5n, 7n])
})

test('verification resumes from the checkpoint but re-checks the anchoring row', { skip }, async () => {
  await appendMany(5)
  await writeCheckpoint(sql!, 'service:admin-api@test')
  await appendMany(3)

  const resumed = await verifyChain(sql!)
  assert.equal(resumed.ok, true)
  // 5 (the anchor) through 8. A verifier that started at 6 would trust a row it never checked.
  assert.equal(resumed.checked, 4)
  assert.equal(resumed.from, 5n)

  // And the anchoring row IS re-checked: edit it and the resumed pass still finds it.
  await sql!`update audit_events set action = 'forged' where seq = 5`
  const after = await verifyChain(sql!)
  assert.equal(after.ok, false)
  assert.ok(after.breaks.some((b) => b.kind === 'hash_mismatch' && b.seq === 5n))
})

test('a checkpoint is only written for a head that verified', { skip }, async () => {
  await appendMany(3)
  const head = await writeCheckpoint(sql!, 'service:admin-api@test')
  assert.equal(head?.seq, 3n)
  const rows = await sql!<{ seq: string; event_count: string }[]>`select seq, event_count from audit_chain_checkpoints`
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.event_count, '3')
})

test('no checkpoint is written for an empty chain', { skip }, async () => {
  assert.equal(await writeCheckpoint(sql!, 'service:admin-api@test'), null)
  const rows = await sql!`select seq from audit_chain_checkpoints`
  assert.equal(rows.length, 0)
})

/* ------------------------------------------------------------------ the fork constraint */

test('THE CHAIN CANNOT FORK: two rows may not share a predecessor', { skip }, async () => {
  await appendMany(3)
  // Row 2's predecessor is row 1. A second row claiming row 1 as ITS predecessor is a fork —
  // which is exactly what two appenders that both read the head before either committed would
  // write, and what an appender that forgets the advisory lock would produce.
  const taken = await sql!<{ prev_hash: string }[]>`select prev_hash from audit_events where seq = 2`

  await assert.rejects(
    async () =>
      sql!`
        insert into audit_events (seq, id, occurred_at, recorded_at, actor, action, subject_kind,
                                  subject_id, outcome, source, payload, prev_hash, hash)
        values (999, gen_random_uuid(), now(), now(), ${OPERATOR_TWO}, 'forged', 'x', 'y',
                'allowed', 'admin-api', '{}'::jsonb, ${taken[0]!.prev_hash}, 'a-different-hash')
      `,
    (err: { code?: string; constraint_name?: string }) => {
      assert.equal(err.code, '23505', 'expected a unique violation')
      assert.equal(err.constraint_name, 'audit_events_chain_uniq')
      return true
    },
  )
  // And appending honestly at the head still works: the constraint refuses a FORK, not growth.
  const head = await chainHead(sql!)
  assert.equal(head.seq, 3n)
  await sql!.begin(async (tx) => {
    await appendAudit(tx, input({ subjectId: 'after-the-forgery' }))
    return { value: null }
  })
  assert.equal((await chainHead(sql!)).seq, 4n)
})

test('concurrent appends serialise into one chain rather than forking', { skip }, async () => {
  // Ten appends started together. The advisory lock queues them; the unique index would refuse
  // any that got past it. Both together are why the result is a chain of exactly ten.
  await Promise.all(
    Array.from({ length: 10 }, (_unused, i) =>
      sql!.begin(async (tx) => {
        await appendAudit(tx, input({ subjectId: `concurrent-${i}` }))
        return { value: null }
      }),
    ),
  )

  const result = await verifyChain(sql!, { from: 0n })
  assert.equal(result.ok, true, shown(result))
  assert.equal(result.totalEvents, 10)
  // And the sequence is gapless, which is what proves the losers retried rather than being lost.
  const seqs = await sql!<{ seq: string }[]>`select seq from audit_events order by seq`
  assert.deepEqual(
    seqs.map((r) => Number(r.seq)),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
  )
})

/* ------------------------------------------------------------------ transactionality */

test('rolling back the change rolls back the audit row', { skip }, async () => {
  // SD-15's verification, verbatim: "rolling back the change also rolls back the audit row, and
  // committing one commits both".
  await assert.rejects(async () =>
    sql!.begin(async (tx) => {
      await appendAudit(tx, input())
      throw new Error('the domain change failed')
    }),
  )
  const rows = await sql!`select seq from audit_events`
  assert.equal(rows.length, 0)
})

test('committing the change commits the audit row', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await tx`insert into feature_flags (key, enabled, description, owner, updated_by)
             values ('a.flag', true, 'a flag', 'platform', ${OPERATOR_ONE})`
    await appendAudit(tx, input({ subjectId: 'a.flag' }))
    return { value: null }
  })
  const flags = await sql!`select key from feature_flags`
  const audit = await sql!`select seq from audit_events`
  assert.equal(flags.length, 1)
  assert.equal(audit.length, 1)
})

/* ------------------------------------------------------------------ the mirror */

test('a mirrored row is recorded once, and a redelivery is refused', { skip }, async () => {
  const eventId = '44444444-4444-4444-8444-444444444444'
  await sql!.begin(async (tx) => {
    await appendAudit(tx, input({ source: 'ledger', sourceEventId: eventId }))
    return { value: null }
  })

  await assert.rejects(
    async () =>
      sql!.begin(async (tx) => {
        await appendAudit(tx, input({ source: 'ledger', sourceEventId: eventId }))
        return { value: null }
      }),
    DuplicateMirrorError,
  )
  const rows = await sql!`select seq from audit_events`
  assert.equal(rows.length, 1)
})

test('two different mirrored rows both land', { skip }, async () => {
  for (const id of ['44444444-4444-4444-8444-444444444444', '55555555-5555-4555-8555-555555555555']) {
    await sql!.begin(async (tx) => {
      await appendAudit(tx, input({ source: 'ledger', sourceEventId: id }))
      return { value: null }
    })
  }
  const rows = await sql!`select seq from audit_events`
  assert.equal(rows.length, 2)
  assert.equal((await verifyChain(sql!, { from: 0n })).ok, true)
})

/* ------------------------------------------------------------------ constraints */

test('an actor must be a principal, not a bare id', { skip }, async () => {
  // The whole "an operator acts as themselves" property rests on `actor` naming a principal. A
  // bare uuid there would be ambiguous between a user and a subject.
  await assert.rejects(
    async () =>
      sql!.begin(async (tx) => {
        await appendAudit(tx, input({ actor: ALICE_BARE }))
        return { value: null }
      }),
    (err: { code?: string; constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'audit_events_actor_is_a_principal')
      return true
    },
  )
})
const ALICE_BARE = '11111111-1111-4111-8111-111111111111'

test('an unknown outcome is refused', { skip }, async () => {
  await assert.rejects(
    async () =>
      sql!`insert into audit_events (seq, id, occurred_at, recorded_at, actor, action, subject_kind,
                                     subject_id, outcome, source, payload, prev_hash, hash)
           values (1, gen_random_uuid(), now(), now(), ${OPERATOR_ONE}, 'a', 'b', 'c',
                   'maybe', 'admin-api', '{}'::jsonb, ${GENESIS_HASH}, 'h')`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'audit_events_outcome_known')
      return true
    },
  )
})

/* ------------------------------------------------------------------ reads */

test('the log reads newest first and pages by cursor', { skip }, async () => {
  await appendMany(7)
  const first = await readAudit(sql!, { limit: 3 })
  assert.deepEqual(first.events.map((e) => Number(e.seq)), [7, 6, 5])
  assert.equal(first.nextCursor, '5')

  const second = await readAudit(sql!, { limit: 3, before: BigInt(first.nextCursor!) })
  assert.deepEqual(second.events.map((e) => Number(e.seq)), [4, 3, 2])

  const last = await readAudit(sql!, { limit: 3, before: BigInt(second.nextCursor!) })
  assert.deepEqual(last.events.map((e) => Number(e.seq)), [1])
  assert.equal(last.nextCursor, null)
})

test('the log filters by correlation id — the 13 §16 workflow', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await appendAudit(tx, input({ correlationId: 'req-hunted' }))
    await appendAudit(tx, input({ correlationId: 'req-other' }))
    await appendAudit(tx, input({ correlationId: 'req-hunted' }))
    return { value: null }
  })
  const page = await readAudit(sql!, { correlationId: 'req-hunted' })
  assert.equal(page.events.length, 2)
  assert.ok(page.events.every((e) => e.correlationId === 'req-hunted'))
})

test('the log filters by actor, action, subject and source', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await appendAudit(tx, input({ actor: OPERATOR_ONE, action: 'admin.flag.changed', subjectId: 'x' }))
    await appendAudit(tx, input({ actor: OPERATOR_TWO, action: 'admin.broadcast.published', subjectKind: 'broadcast', subjectId: 'y' }))
    await appendAudit(tx, input({ actor: OPERATOR_TWO, action: 'ledger.entry.reversed', source: 'ledger', sourceEventId: '66666666-6666-4666-8666-666666666666', subjectId: 'z' }))
    return { value: null }
  })
  assert.equal((await readAudit(sql!, { actor: OPERATOR_TWO })).events.length, 2)
  assert.equal((await readAudit(sql!, { action: 'admin.flag.changed' })).events.length, 1)
  assert.equal((await readAudit(sql!, { subjectKind: 'broadcast' })).events.length, 1)
  assert.equal((await readAudit(sql!, { subjectId: 'z' })).events.length, 1)
  assert.equal((await readAudit(sql!, { source: 'ledger' })).events.length, 1)
})

test('the read limit is clamped rather than trusted', { skip }, async () => {
  await appendMany(3)
  assert.equal((await readAudit(sql!, { limit: 100_000 })).events.length, 3)
  assert.equal((await readAudit(sql!, { limit: -5 })).events.length, 1)
})
