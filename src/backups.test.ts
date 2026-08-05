/**
 * The backup and restore invariants — proved against a real Postgres, not asserted about.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **EVERY TEST HERE THAT MATTERS BYPASSES THE APPLICATION AND WRITES SQL DIRECTLY.**
 *
 * That is deliberate and it is the whole value of the file. The claim being made is not "the route
 * refuses this" — a route is code somebody edits — but "the DATABASE refuses this, to any caller,
 * through any door, including psql". A test that went through `requestRestore` for the environment
 * refusal would be testing the `if` statement in `requestRestore`, and would keep passing on the
 * day somebody deletes it.
 *
 * So the environment tests insert into `restore_runs` directly and assert the trigger fires.
 *
 * **THE FIXTURE ESTATE IS `testnet`, NEVER `mainnet`** (`testsupport.ts` `TEST_ENVIRONMENT`). A
 * cross-environment fixture therefore has to name `mainnet` explicitly, which means the dangerous
 * direction — a mainnet artefact meeting a testnet estate, or the reverse — is always spelled out
 * in the test rather than arrived at by default.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import {
  BackupError,
  EnvironmentMismatchError,
  assertRootPath,
  expectedConfirmation,
  findBackup,
  listBackups,
  protectionFor,
  readEstateIdentity,
  readSettings,
  requestBackup,
  requestRestore,
  updateSettings,
} from './backups.ts'
import { db, enabled, migrateTestDb, openDb, resetAdminApi, skip, TEST_ENVIRONMENT } from './testsupport.ts'

let sql: postgres.Sql | null = null

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
})
beforeEach(async () => {
  if (sql) await resetAdminApi(sql)
})
after(async () => {
  if (sql) await sql.end({ timeout: 5 })
})

/** A succeeded backup row, written directly so its environment can be chosen. */
async function seedBackup(
  s: postgres.Sql,
  environment: string,
  overrides: { state?: string; queuedAt?: string } = {},
): Promise<string> {
  const state = overrides.state ?? 'succeeded'
  const evidenced = state === 'succeeded'
  const rows = await s<{ id: string }[]>`
    insert into backup_runs (
      environment, compose_project, kind, state, requested_by, root_path, directory,
      queued_at, finished_at, total_bytes, artefact_count, manifest_sha256, error
    ) values (
      ${environment}, ${'cf-testnet'}, 'full', ${state}, 'user:11111111-1111-1111-1111-111111111111',
      '/backups', ${evidenced ? `/backups/${environment}/20260805T000000Z` : null},
      ${overrides.queuedAt ?? '2026-08-05T09:00:00Z'}::timestamptz,
      ${state === 'queued' || state === 'running' ? null : '2026-08-05T09:05:00Z'}::timestamptz,
      ${evidenced ? '1024' : null}::bigint, ${evidenced ? 3 : null},
      ${evidenced ? 'a'.repeat(64) : null},
      ${state === 'failed' ? 'pg_dump exited 1' : null}
    ) returning id
  `
  return rows[0]!.id
}

/* ------------------------------------------------------------------ the estate's own identity */

test('the estate identity cannot be changed, once claimed', { skip }, async () => {
  const s = sql!
  const identity = await readEstateIdentity(db(s))
  assert.equal(identity?.environment, TEST_ENVIRONMENT)

  // ── THE POINT. If this row could be edited, a compose-file change could re-label a testnet
  //    estate as mainnet and thereby UNLOCK the restore the whole design exists to refuse. The
  //    trigger is what makes the label a fact rather than a setting.
  await assert.rejects(
    () => s`update estate_identity set environment = 'mainnet' where singleton`,
    /claimed once and cannot be changed/,
    'an estate must not be able to re-label itself',
  )
  await assert.rejects(
    () => s`delete from estate_identity where singleton`,
    /claimed once and cannot be changed/,
    'deleting the row would let the next boot claim a different environment',
  )
})

/* ------------------------------------------------------------- THE CROSS-ENVIRONMENT REFUSAL */

test(
  'A TESTNET BACKUP CANNOT BE RESTORED INTO A MAINNET ESTATE — refused by the schema, not the route',
  { skip },
  async () => {
    const s = sql!
    // The estate is `testnet`. This backup claims to be `mainnet`, which is exactly the shape of
    // artefact that would arrive if somebody copied a catalogue between environments — or if the
    // 2026-08-05 seeder defect had stamped a run with the wrong project.
    const foreign = await seedBackup(s, 'mainnet')

    await assert.rejects(
      () => s`
        insert into restore_runs (backup_run_id, environment, mode, requested_by)
        values (${foreign}, 'testnet', 'verify', 'user:22222222-2222-2222-2222-222222222222')
      `,
      /REFUSED: that backup was taken in the mainnet estate and this is the testnet estate/,
      'the trigger must refuse a cross-environment restore even when the caller writes raw SQL',
    )

    // ...and it is refused no matter WHAT the caller puts in `environment`, because the column is
    // overwritten from the backup before the comparison. Claiming to be mainnet does not help.
    await assert.rejects(
      () => s`
        insert into restore_runs (backup_run_id, environment, mode, requested_by)
        values (${foreign}, 'mainnet', 'verify', 'user:22222222-2222-2222-2222-222222222222')
      `,
      /REFUSED: that backup was taken in the mainnet estate/,
      'the environment is DERIVED from the backup — a caller cannot supply one that agrees',
    )
  },
)

test('the environment is copied off the backup, never taken from the request', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)
  // A caller lying about the environment in the direction that would otherwise "work".
  const rows = await s<{ environment: string }[]>`
    insert into restore_runs (backup_run_id, environment, mode, requested_by)
    values (${backup}, 'development', 'verify', 'user:22222222-2222-2222-2222-222222222222')
    returning environment
  `
  assert.equal(
    rows[0]?.environment,
    TEST_ENVIRONMENT,
    'the stored environment must be the BACKUP’s, discarding whatever the caller wrote',
  )
})

test('requestRestore reports the mismatch in a sentence before the trigger does', { skip }, async () => {
  const s = sql!
  const foreign = await seedBackup(s, 'mainnet')
  await assert.rejects(
    () =>
      db(s).begin(async (tx) => ({
        value: await requestRestore(tx, {
          backupRunId: foreign,
          mode: 'verify',
          targets: [],
          requestedBy: 'user:22222222-2222-2222-2222-222222222222',
          reason: null,
          approvalId: null,
          confirmation: null,
          correlationId: null,
        }),
      })),
    (err: unknown) =>
      err instanceof EnvironmentMismatchError &&
      err.backupEnvironment === 'mainnet' &&
      err.estateEnvironment === TEST_ENVIRONMENT,
  )
})

/* --------------------------------------------------------------- a restore is never one click */

test('a live restore cannot exist without BOTH an approval and a typed confirmation', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)

  // ── TWO LAYERS, AND THEY FIRE IN A DEFINITE ORDER. The BEFORE INSERT trigger runs first, so an
  //    absent approval is caught there and never reaches the CHECK. Both are asserted, because the
  //    CHECK is what still holds if the trigger is ever dropped — and a test that only exercised
  //    the outer layer would go green on a database missing the inner one.
  await assert.rejects(
    () => s`
      insert into restore_runs (backup_run_id, environment, mode, requested_by)
      values (${backup}, ${TEST_ENVIRONMENT}, 'live', 'user:22222222-2222-2222-2222-222222222222')
    `,
    /is not an approved estate.restore approval/,
    'a live restore naming no approval is refused by the trigger',
  )

  await assert.rejects(
    () => s`
      insert into restore_runs (backup_run_id, environment, mode, requested_by, confirmation)
      values (${backup}, ${TEST_ENVIRONMENT}, 'live', 'user:22222222-2222-2222-2222-222222222222', 'restore testnet from 2026-08-05T09:00:00Z')
    `,
    /is not an approved estate.restore approval/,
    'a confirmation without a second operator is one pair of eyes',
  )

  // Past the trigger — a real, approved, correctly-targeted approval — the CHECK is what refuses a
  // live restore that names no typed confirmation.
  const appr = await s<{ id: string }[]>`
    insert into approvals (action, subject_kind, subject_id, reason_code, reason, requested_by,
                           expires_at, state, decided_by, decided_at)
    values ('estate.restore', 'backup_run', ${backup}, 'incident', 'restoring after data loss',
            'user:11111111-1111-1111-1111-111111111111', now() + interval '1 hour', 'approved',
            'user:22222222-2222-2222-2222-222222222222', now())
    returning id
  `
  await assert.rejects(
    () => s`
      insert into restore_runs (backup_run_id, environment, mode, requested_by, approval_id)
      values (${backup}, ${TEST_ENVIRONMENT}, 'live', 'user:33333333-3333-3333-3333-333333333333',
              ${appr[0]!.id})
    `,
    /restore_runs_live_is_confirmed/,
    'two operators are not enough on their own — the phrase names WHICH backup they agreed to',
  )
})

test('a live restore must name an approval FOR THAT BACKUP, approved', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)
  const other = await seedBackup(s, TEST_ENVIRONMENT)

  // An approval two operators drove to `approved` — but for a DIFFERENT backup.
  const appr = await s<{ id: string }[]>`
    insert into approvals (action, subject_kind, subject_id, reason_code, reason, requested_by,
                           expires_at, state, decided_by, decided_at)
    values ('estate.restore', 'backup_run', ${other}, 'incident', 'restoring after data loss',
            'user:11111111-1111-1111-1111-111111111111', now() + interval '1 hour', 'approved',
            'user:22222222-2222-2222-2222-222222222222', now())
    returning id
  `
  const approvalId = appr[0]!.id

  await assert.rejects(
    () => s`
      insert into restore_runs (backup_run_id, environment, mode, requested_by, approval_id, confirmation)
      values (${backup}, ${TEST_ENVIRONMENT}, 'live', 'user:33333333-3333-3333-3333-333333333333',
              ${approvalId}, 'restore testnet from 2026-08-05T09:00:00Z')
    `,
    /authorises restoring backup .*, not backup /,
    'an approval is consent to restore ONE backup — reusing it for another is not consent',
  )
})

test('a backup that did not succeed cannot be restored from', { skip }, async () => {
  const s = sql!
  const failed = await seedBackup(s, TEST_ENVIRONMENT, { state: 'failed' })
  await assert.rejects(
    () => s`
      insert into restore_runs (backup_run_id, environment, mode, requested_by)
      values (${failed}, ${TEST_ENVIRONMENT}, 'verify', 'user:22222222-2222-2222-2222-222222222222')
    `,
    /not succeeded — restoring from an incomplete set/,
    'a partial set half-overwrites live data, which is worse than not restoring',
  )
})

test('one approval authorises exactly one live restore, for ever', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)
  const appr = await s<{ id: string }[]>`
    insert into approvals (action, subject_kind, subject_id, reason_code, reason, requested_by,
                           expires_at, state, decided_by, decided_at)
    values ('estate.restore', 'backup_run', ${backup}, 'incident', 'restoring after data loss',
            'user:11111111-1111-1111-1111-111111111111', now() + interval '1 hour', 'approved',
            'user:22222222-2222-2222-2222-222222222222', now())
    returning id
  `
  const approvalId = appr[0]!.id
  const confirmation = 'restore testnet from 2026-08-05T09:00:00Z'

  await s`
    insert into restore_runs (backup_run_id, environment, mode, requested_by, approval_id, confirmation)
    values (${backup}, ${TEST_ENVIRONMENT}, 'live', 'user:33333333-3333-3333-3333-333333333333',
            ${approvalId}, ${confirmation})
  `
  // A retry must fail at the index rather than start a second restore over the top of the first.
  await assert.rejects(
    () => s`
      insert into restore_runs (backup_run_id, environment, mode, requested_by, approval_id, confirmation)
      values (${backup}, ${TEST_ENVIRONMENT}, 'live', 'user:33333333-3333-3333-3333-333333333333',
              ${approvalId}, ${confirmation})
    `,
    /restore_runs_one_live_per_approval/,
  )
})

test('only one restore may be in flight across the estate', { skip }, async () => {
  const s = sql!
  const first = await seedBackup(s, TEST_ENVIRONMENT)
  const second = await seedBackup(s, TEST_ENVIRONMENT)

  await db(s).begin(async (tx) => ({
    value: await requestRestore(tx, {
      backupRunId: first,
      mode: 'verify',
      targets: [],
      requestedBy: 'user:22222222-2222-2222-2222-222222222222',
      reason: null,
      approvalId: null,
      confirmation: null,
      correlationId: null,
    }),
  }))

  await assert.rejects(
    () =>
      db(s).begin(async (tx) => ({
        value: await requestRestore(tx, {
          backupRunId: second,
          mode: 'verify',
          targets: [],
          requestedBy: 'user:22222222-2222-2222-2222-222222222222',
          reason: null,
          approvalId: null,
          confirmation: null,
          correlationId: null,
        }),
      })),
    /already queued|already running/,
    'two restores would be two processes rewriting the same databases',
  )
})

/* -------------------------------------------------------------------- the confirmation phrase */

test('the confirmation phrase names what, from when, and into which environment', { skip }, () => {
  const phrase = expectedConfirmation({
    environment: 'mainnet',
    queuedAt: '2026-08-05T09:00:00.123Z',
  })
  assert.equal(phrase, 'restore mainnet from 2026-08-05T09:00:00Z')
  // Second granularity: a phrase carrying milliseconds cannot be transcribed from a rendered
  // timestamp, and a confirmation nobody can type is one that gets pasted from the error message.
  assert.ok(!phrase.includes('.123'))
  // The environment is IN the phrase, so the same backup taken in two estates yields two phrases.
  assert.notEqual(
    phrase,
    expectedConfirmation({ environment: 'testnet', queuedAt: '2026-08-05T09:00:00.123Z' }),
  )
})

test('a live restore with the wrong confirmation is refused, and told the right one', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)
  await assert.rejects(
    () =>
      db(s).begin(async (tx) => ({
        value: await requestRestore(tx, {
          backupRunId: backup,
          mode: 'live',
          targets: [],
          requestedBy: 'user:22222222-2222-2222-2222-222222222222',
          reason: null,
          approvalId: '11111111-1111-1111-1111-111111111111',
          confirmation: 'restore',
          correlationId: null,
        }),
      })),
    /must be exactly "restore testnet from 2026-08-05T09:00:00Z"/,
  )
})

/* ------------------------------------------------------- a success carries its own evidence */

test('a backup cannot be recorded as succeeded without a checksum', { skip }, async () => {
  const s = sql!
  await assert.rejects(
    () => s`
      insert into backup_runs (environment, compose_project, kind, state, requested_by, root_path,
                               finished_at)
      values (${TEST_ENVIRONMENT}, 'cf-testnet', 'full', 'succeeded',
              'user:11111111-1111-1111-1111-111111111111', '/backups', now())
    `,
    /backup_runs_success_is_evidenced/,
    'a backup whose integrity is unverified is a guess, and must not be able to claim success',
  )
})

test('"verified" must name the restore that proved it', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)
  await assert.rejects(
    () => s`update backup_runs set verified_at = now() where id = ${backup}`,
    /backup_runs_verification_is_attributed/,
    'a green tick with nothing to point at is the reassuring lie this design exists to refuse',
  )
})

/* ------------------------------------------------------------------- key material never lands */

test('a secrets artefact names a PUBLIC ADDRESS, and the shape refuses a private key', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)

  // A 64-hex secp256k1 private key is exactly what must never end up in this column. The CHECK
  // refuses it by shape: an address is 0x + 40 hex, a key is 64 hex.
  await assert.rejects(
    () => s`
      insert into backup_artefacts (run_id, kind, name, rel_path, bytes, sha256, public_ref)
      values (${backup}, 'secrets', 'miner-coinbase', 'secrets/m.json.age', 512, ${'b'.repeat(64)},
              ${`0x${'c'.repeat(64)}`})
    `,
    /backup_artefacts_public_ref_is_an_address/,
    'the column must be unable to hold a private key even if a caller tries to put one there',
  )

  await assert.rejects(
    () => s`
      insert into backup_artefacts (run_id, kind, name, rel_path, bytes, sha256)
      values (${backup}, 'secrets', 'miner-coinbase', 'secrets/m.json.age', 512, ${'b'.repeat(64)})
    `,
    /backup_artefacts_secrets_name_their_address/,
    'a key artefact with no address cannot be verified by address comparison, which is the only ' +
      'verification that proves a recovery without printing the key',
  )

  // The legitimate shape.
  await s`
    insert into backup_artefacts (run_id, kind, name, rel_path, bytes, sha256, public_ref)
    values (${backup}, 'secrets', 'miner-coinbase-mainnet', 'secrets/miner.json.age', 512,
            ${'b'.repeat(64)}, '0x980d52a868d41a34a186ce890874c8e547975b45')
  `
})

test('an artefact path is relative and cannot traverse', { skip }, async () => {
  const s = sql!
  const backup = await seedBackup(s, TEST_ENVIRONMENT)
  // A manifest is UNTRUSTED INPUT — it arrives from a disk anybody with the host could edit. An
  // absolute path in it is a write primitive aimed anywhere on the restoring machine.
  for (const bad of ['/etc/passwd', '../../etc/passwd', 'db/../../../etc/passwd']) {
    await assert.rejects(
      () => s`
        insert into backup_artefacts (run_id, kind, name, rel_path, bytes, sha256)
        values (${backup}, 'database', ${`x-${bad}`}, ${bad}, 10, ${'d'.repeat(64)})
      `,
      /backup_artefacts_rel_path_is_relative/,
      `a manifest naming ${bad} must be refused`,
    )
  }
})

/* ------------------------------------------------------------------------------- the settings */

test('the backup root is validated in the application AND in the schema', { skip }, async () => {
  const s = sql!
  for (const bad of ['relative/path', '/data/../etc', '/data/x;rm -rf /', '/data/$(whoami)']) {
    assert.throws(() => assertRootPath(bad), BackupError, `${bad} must be refused`)
  }
  assert.equal(assertRootPath('/data/cloudsforge-backups'), '/data/cloudsforge-backups')

  // ...and the database refuses it too, for the caller that never goes through the route.
  await assert.rejects(
    () => s`update backup_settings set root_path = '/data/../etc' where singleton`,
    /backup_settings_root_is_absolute/,
  )
})

test('the ceiling cannot be raised past the disk it protects', { skip }, async () => {
  const s = sql!
  // 1 TiB is the roof, chosen below the 1.4 TB free on /dev/sdb1 so that the SETTING cannot be
  // used to fill the disk that also holds 553 GB of chain data.
  await assert.rejects(
    () => s`update backup_settings set ceiling_bytes = 2199023255552 where singleton`,
    /backup_settings_ceiling_sane/,
  )
  await assert.rejects(
    () => s`update backup_settings set retention_copies = 0 where singleton`,
    /backup_settings_retention_sane/,
  )
})

test('settings round-trip through the application', { skip }, async () => {
  const s = sql!
  const updated = await db(s).begin(async (tx) => ({
    value: await updateSettings(
      tx,
      { rootPath: '/data/cloudsforge-backups', retentionCopies: 30 },
      'user:11111111-1111-1111-1111-111111111111',
    ),
  }))
  assert.equal(updated.value.rootPath, '/data/cloudsforge-backups')
  assert.equal(updated.value.retentionCopies, 30)
  // Untouched fields keep their values rather than reverting to defaults — a settings PUT that
  // silently reset the schedule would be a backup that stopped running for a reason nobody saw.
  assert.equal(updated.value.scheduleEveryMinutes, 1440)
  assert.equal((await readSettings(db(s))).rootPath, '/data/cloudsforge-backups')
})

/* ------------------------------------------------------------------------------- the honesty */

test('the protection statement never promises off-site safety', { skip }, async () => {
  const settings = await readSettings(db(sql!))
  const protection = protectionFor(settings)

  assert.equal(protection.sameHost, true, 'the backups are on the same machine and must say so')
  assert.equal(protection.custodyKeyringIncluded, false)

  const notCovered = protection.doesNotCover.join(' ').toLowerCase()
  for (const risk of ['theft', 'fire', 'ransomware', 'rm -rf', 'off-site']) {
    assert.ok(notCovered.includes(risk), `the uncovered risks must name ${risk} explicitly`)
  }

  // The separation rule, rendered. If the age identity or the custody keyring ever moved onto the
  // backup disk, one artefact would be simultaneously the coins and the key to them.
  const offMachine = protection.mustLeaveTheMachine.join(' ')
  assert.match(offMachine, /CUSTODY_MASTER_SECRET/)
  assert.match(offMachine, /age identity/)
})

/* ------------------------------------------------------------------------ the ordinary path */

test('a backup is queued with the estate’s own environment and the settings root', { skip }, async () => {
  const s = sql!
  const queued = await db(s).begin(async (tx) => ({
    value: await requestBackup(tx, {
      kind: 'full',
      requestedBy: 'user:11111111-1111-1111-1111-111111111111',
      reason: 'before a risky migration',
      composeProject: 'cf-testnet',
      correlationId: 'req-1',
    }),
  }))
  assert.equal(queued.value.environment, TEST_ENVIRONMENT)
  assert.equal(queued.value.state, 'queued')
  assert.equal(queued.value.rootPath, '/backups')
  // Nothing has run, so there is no evidence yet — and the row must not pretend otherwise.
  assert.equal(queued.value.manifestSha256, null)
  assert.equal(queued.value.verifiedAt, null, 'a fresh backup has never been restored')

  assert.equal((await listBackups(db(s))).length, 1)
  assert.equal((await findBackup(db(s), queued.value.id))?.id, queued.value.id)
})
