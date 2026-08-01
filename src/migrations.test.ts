/**
 * The schema.
 *
 * Two questions this file answers that a running service cannot:
 *
 *   1. **Do the constraints actually fire?** Each of the four this service exists to add is
 *      exercised directly, with every layer above it bypassed. A constraint that was written but
 *      never triggered is a comment.
 *   2. **Is the migration set applicable twice, and to a database that is not empty?** 17 §9:
 *      "a migration that ran once on an empty database" does not count as done.
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { migrate } from '@cloudsforge/db'
import type { Sql as DbSql } from '@cloudsforge/db'
import { BASELINE_VERSION, MIGRATIONS, SCHEMA_VERSION, SEQUENCES, TABLES } from './migrations.ts'
import { GENESIS_HASH } from './audit.ts'
import { OPERATOR_ONE, OPERATOR_TWO, enabled, migrateTestDb, openDb, resetAdminApi, skip } from './testsupport.ts'

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

/* ------------------------------------------------------------------ the set itself */

test('versions are unique and monotonic', () => {
  const versions = MIGRATIONS.map((m) => m.version)
  assert.deepEqual(versions, [...versions].sort((a, b) => a - b))
  assert.equal(new Set(versions).size, versions.length)
})

test('the schema version is the highest migration, and the baseline is zero', () => {
  assert.equal(SCHEMA_VERSION, Math.max(...MIGRATIONS.map((m) => m.version)))
  // Nothing to baseline against: this service is derived from nimbus's admin proxies, and a proxy
  // has no schema. Nimbus's audit is a `log.warn` line (SD-11).
  assert.equal(BASELINE_VERSION, 0)
})

test('every table the harness truncates exists, and every table that exists is truncated', { skip }, async () => {
  // A table missing from TABLES is a table that leaks state between test files, which is the
  // hardest class of flake to diagnose.
  const rows = await sql!<{ tablename: string }[]>`
    select tablename from pg_tables where schemaname = 'public'
  `
  const live = new Set(rows.map((r) => r.tablename))
  live.delete('schema_migrations')
  live.delete('jobs') // truncated explicitly alongside TABLES
  assert.deepEqual([...live].sort(), [...TABLES].sort())
})

test('every named sequence exists', { skip }, async () => {
  for (const sequence of SEQUENCES) {
    const rows = await sql!`select 1 from pg_sequences where sequencename = ${sequence}`
    assert.equal(rows.length, 1, `${sequence} is named by the harness but does not exist`)
  }
})

test('MIGRATIONS ARE IDEMPOTENT AGAINST A NON-EMPTY DATABASE', { skip }, async () => {
  // 17 §9: "a migration that ran once on an empty database" is not done. So: put real rows in,
  // then run the whole set again.
  await sql!.begin(async (tx) => {
    await tx`insert into audit_events (seq, id, occurred_at, recorded_at, actor, action,
                                       subject_kind, subject_id, outcome, source, payload,
                                       prev_hash, hash)
             values (1, gen_random_uuid(), now(), now(), ${OPERATOR_ONE}, 'a', 'b', 'c',
                     'allowed', 'admin-api', '{}'::jsonb, ${GENESIS_HASH}, 'hash-1')`
    await tx`insert into feature_flags (key, enabled, description, owner, updated_by)
             values ('a.flag', true, 'd', 'platform', ${OPERATOR_ONE})`
    return { value: null }
  })

  const result = await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'admin-api-test' })
  assert.deepEqual(result.applied, [], 'a second run must apply nothing')
  assert.equal((await sql!`select seq from audit_events`).length, 1, 'and must not lose the rows')
})

test('a modified released migration is refused', { skip }, async () => {
  // Two databases would then disagree about what "version 5" is, silently.
  const tampered = MIGRATIONS.map((m) =>
    m.version === 5 ? { ...m, up: `${m.up}\n-- an edit after release` } : m,
  )
  await assert.rejects(
    async () => migrate(sql as unknown as DbSql, tampered, { service: 'admin-api-test' }),
    /was modified after it was applied/,
  )
})

/* ------------------------------------------------------------------ the four constraints */

async function insertAudit(seq: number, prevHash: string, hash: string): Promise<void> {
  await sql!`insert into audit_events (seq, id, occurred_at, recorded_at, actor, action,
                                       subject_kind, subject_id, outcome, source, payload,
                                       prev_hash, hash)
             values (${seq}, gen_random_uuid(), now(), now(), ${OPERATOR_ONE}, 'a', 'b', 'c',
                     'allowed', 'admin-api', '{}'::jsonb, ${prevHash}, ${hash})`
}

test('CONSTRAINT audit_events_chain_uniq: one predecessor, one successor', { skip }, async () => {
  await insertAudit(1, GENESIS_HASH, 'hash-1')
  await assert.rejects(
    async () => insertAudit(2, GENESIS_HASH, 'hash-2'),
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'audit_events_chain_uniq')
      return true
    },
  )
  // And a legitimate successor lands, so the constraint refuses a FORK rather than growth.
  await insertAudit(2, 'hash-1', 'hash-2')
})

test('CONSTRAINT audit_events_hash_uniq: no two rows share a hash', { skip }, async () => {
  await insertAudit(1, GENESIS_HASH, 'hash-1')
  await assert.rejects(
    async () => insertAudit(2, 'hash-1', 'hash-1'),
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'audit_events_hash_uniq')
      return true
    },
  )
})

test('CONSTRAINT audit_events_source_event_uniq: a mirror row lands once', { skip }, async () => {
  const eventId = '77777777-7777-4777-8777-777777777777'
  await sql!`insert into audit_events (seq, id, occurred_at, recorded_at, actor, action,
                                       subject_kind, subject_id, outcome, source, source_event_id,
                                       payload, prev_hash, hash)
             values (1, gen_random_uuid(), now(), now(), ${OPERATOR_ONE}, 'a', 'b', 'c',
                     'allowed', 'ledger', ${eventId}, '{}'::jsonb, ${GENESIS_HASH}, 'hash-1')`
  await assert.rejects(
    async () =>
      sql!`insert into audit_events (seq, id, occurred_at, recorded_at, actor, action,
                                     subject_kind, subject_id, outcome, source, source_event_id,
                                     payload, prev_hash, hash)
           values (2, gen_random_uuid(), now(), now(), ${OPERATOR_ONE}, 'a', 'b', 'c',
                   'allowed', 'ledger', ${eventId}, '{}'::jsonb, 'hash-1', 'hash-2')`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'audit_events_source_event_uniq')
      return true
    },
  )
  // NULL source_event_id is legal any number of times — local rows are not mirrored rows.
  await insertAudit(3, 'hash-1', 'hash-3')
  await insertAudit(4, 'hash-3', 'hash-4')
})

async function insertApproval(requestedBy = OPERATOR_ONE): Promise<string> {
  const rows = await sql!<{ id: string }[]>`
    insert into approvals (action, subject_kind, subject_id, reason_code, reason, requested_by, expires_at)
    values ('ledger.entry.reverse', 'ledger_entry', 'e-1', 'data_correction', 'r',
            ${requestedBy}, now() + interval '1 hour')
    returning id
  `
  return rows[0]!.id
}

test('CONSTRAINT approvals_decision_is_attributed: a decision names its decider', { skip }, async () => {
  const id = await insertApproval()
  await assert.rejects(
    async () => sql!`update approvals set state = 'approved' where id = ${id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_decision_is_attributed')
      return true
    },
  )
  // And an expiry, which nobody decided, must carry NO decider — which is what makes it
  // unexecutable by construction.
  await assert.rejects(
    async () =>
      sql!`update approvals set state = 'expired', decided_by = ${OPERATOR_TWO}, decided_at = now()
            where id = ${id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_decision_is_attributed')
      return true
    },
  )
})

test('CONSTRAINT approvals_execution_is_complete: an outcome and a time move together', { skip }, async () => {
  const id = await insertApproval()
  await sql!`update approvals set state = 'approved', decided_by = ${OPERATOR_TWO}, decided_at = now()
              where id = ${id}`
  await assert.rejects(
    async () => sql!`update approvals set executed_at = now() where id = ${id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_execution_is_complete')
      return true
    },
  )
})

test('CONSTRAINT approvals_state_known: an invented state is refused', { skip }, async () => {
  const id = await insertApproval()
  await assert.rejects(
    async () => sql!`update approvals set state = 'probably-fine' where id = ${id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'approvals_state_known')
      return true
    },
  )
})

/* ------------------------------------------------------------------ flags and broadcasts */

test('CONSTRAINT feature_flags_owner_named: a flag nobody owns cannot exist', { skip }, async () => {
  await assert.rejects(
    async () =>
      sql!`insert into feature_flags (key, enabled, description, owner, updated_by)
           values ('a.flag', true, 'd', '', ${OPERATOR_ONE})`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'feature_flags_owner_named')
      return true
    },
  )
})

test('CONSTRAINT feature_flags_key_shape: a key is a key, not a sentence', { skip }, async () => {
  for (const key of ['Not A Key', 'a', '../etc/passwd', 'UPPER.case']) {
    await assert.rejects(
      async () =>
        sql!`insert into feature_flags (key, enabled, description, owner, updated_by)
             values (${key}, true, 'd', 'platform', ${OPERATOR_ONE})`,
      (err: { constraint_name?: string }) => {
        assert.equal(err.constraint_name, 'feature_flags_key_shape', `${key} should be refused`)
        return true
      },
    )
  }
  await sql!`insert into feature_flags (key, enabled, description, owner, updated_by)
             values ('market.listing_enabled', true, 'd', 'platform', ${OPERATOR_ONE})`
})

test('CONSTRAINT broadcasts_window_ordered: a notice cannot end before it starts', { skip }, async () => {
  await assert.rejects(
    async () =>
      sql!`insert into broadcasts (severity, title, body, starts_at, ends_at, published_by)
           values ('info', 't', 'b', now(), now() - interval '1 hour', ${OPERATOR_ONE})`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'broadcasts_window_ordered')
      return true
    },
  )
})

test('CONSTRAINT broadcasts_retraction_is_attributed: a retraction names who did it', { skip }, async () => {
  const rows = await sql!<{ id: string }[]>`
    insert into broadcasts (severity, title, body, published_by)
    values ('info', 't', 'b', ${OPERATOR_ONE}) returning id
  `
  await assert.rejects(
    async () => sql!`update broadcasts set retracted_at = now() where id = ${rows[0]!.id}`,
    (err: { constraint_name?: string }) => {
      assert.equal(err.constraint_name, 'broadcasts_retraction_is_attributed')
      return true
    },
  )
})

/* ------------------------------------------------------------------ what is NOT here */

test('THIS SERVICE HOLDS NO MONEY AND NO SECOND COPY OF ANOTHER SERVICE\'S TABLE', { skip }, async () => {
  // A BFF composes and audits. The moment a column here starts being read as the truth about
  // another service's state, both have stopped being able to migrate independently.
  const columns = await sql!<{ table_name: string; column_name: string }[]>`
    select table_name, column_name from information_schema.columns
     where table_schema = 'public'
  `
  const forbidden = /^(balance|amount|held_amount|escrow_balance|available|liability)$/
  const offenders = columns.filter((c) => forbidden.test(c.column_name))
  assert.deepEqual(offenders, [], 'a balance column here means this service has become a second ledger')

  const tables = new Set(columns.map((c) => c.table_name))
  for (const foreign of ['users', 'listings', 'entries', 'entitlements', 'wallets', 'sessions']) {
    assert.ok(!tables.has(foreign), `${foreign} belongs to another service`)
  }
})
