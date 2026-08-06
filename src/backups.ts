/**
 * Backup and restore — the control plane.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS FILE NEVER TOUCHES A BYTE OF A BACKUP.** It owns the catalogue, the authority to start a
 * run, the environment invariant and the audit row. The bytes belong to `deploy/backup`, a separate
 * deployable that leases `backup.*` jobs out of this service's own `jobs` table.
 *
 * The split is forced and it is also correct. Rule 1 gives a service exactly one database and CI
 * greps this repository's source for a second DSN, so a process that dumps twenty-nine OTHER
 * databases cannot live here. It should not anyway: reading every database in the cluster is a
 * different trust domain from composing an operator's console, and collapsing the two would mean a
 * compromise of the console is a compromise of every database in the estate.
 *
 * `JobRunner.claim()` filters by REGISTERED kind (`runtime/packages/jobs/src/index.ts`), so
 * this service enqueues work it will never claim and the runner claims work nothing else will take.
 * If no runner is deployed the rows sit `queued` for ever — and the console says exactly that,
 * which is the honest reading. A queue that silently discarded unclaimable work would show an
 * operator a backup that was never taken.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE ONE RULE, INHERITED FROM `deploy/docs/custody-backup-restore.md`.**
 *
 * Never print, echo, log or return a master secret, a private key, a mnemonic or an xprv. On
 * 2026-08-05 three of the estate's four custody keyrings had to be rotated because agent sessions
 * PRINTED them — nothing was stolen, and a printed secret is an exposed secret regardless.
 *
 * So: nothing in this file, and nothing any route in this file serves, can carry key material.
 * A backup set contains the custody VAULT — ciphertext — and never the keyring that opens it.
 * `custodyKeyringIncluded` below is a hard-coded `false` rather than a column, because a column
 * could one day be set to true, and the two artefacts sharing one medium is the single failure
 * that turns an encrypted backup into a plaintext key store with extra steps
 * (`custody-backup-restore.md` §1.5). The console shows that a custody backup EXISTS. It can never
 * show what is in it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Db, Tx } from './outbox.ts'

/** The environments an estate can be. Closed, and pinned by `estate_identity_known` in the schema. */
export const ENVIRONMENTS: readonly string[] = Object.freeze(['mainnet', 'testnet', 'development'])

export type Environment = 'mainnet' | 'testnet' | 'development'
export type BackupKind = 'full' | 'databases' | 'custody' | 'files'
export type BackupState = 'queued' | 'running' | 'succeeded' | 'failed' | 'pruned'
export type RestoreMode = 'verify' | 'live'
export type RestoreState = 'queued' | 'running' | 'succeeded' | 'failed' | 'refused'

/** The job kinds the data plane claims. Declared here because this service is what enqueues them. */
export const BACKUP_RUN = 'backup.run'
export const BACKUP_RESTORE = 'backup.restore'
export const BACKUP_VERIFY = 'backup.verify'
export const BACKUP_PRUNE = 'backup.prune'

export class BackupError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BackupError'
  }
}

/** The environment gate refused. Distinct from every other 400 so a console can say WHY. */
export class EnvironmentMismatchError extends Error {
  readonly backupEnvironment: string
  readonly estateEnvironment: string
  constructor(backupEnvironment: string, estateEnvironment: string) {
    super(
      `REFUSED: that backup was taken in the ${backupEnvironment} estate and this is the ` +
        `${estateEnvironment} estate — a cross-environment restore destroys real balances`,
    )
    this.name = 'EnvironmentMismatchError'
    this.backupEnvironment = backupEnvironment
    this.estateEnvironment = estateEnvironment
  }
}

/* ---------------------------------------------------------------- the estate's claimed identity */

/**
 * Claim this estate's identity, once, for ever.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS IS THE DEFENCE AGAINST THE DEFECT THAT ALREADY HAPPENED TWICE ON 2026-08-05.**
 *
 * The estate seeder ran `docker compose` against the MAINNET project regardless of which
 * environment it had been asked to act on, so a testnet action recreated a mainnet container. A
 * restore carrying that bug overwrites real balances with test ones, irreversibly.
 *
 * The lesson is precise and it is not "validate the parameter": the parameter WAS validated, and
 * then ignored. A target that is passed in is a target that can be passed wrongly. So the
 * environment is a FACT ON BOTH SIDES — written into the backup artefact when it is taken, written
 * into this row when the estate is first brought up — and a restore compares two discovered facts.
 * Neither is a request field. `restore_runs_environment_matches()` in migration 10 does the
 * comparing, in the schema, where a route rewrite cannot reach it.
 *
 * Immutable by trigger. An estate that could re-label itself could unlock exactly the restore this
 * exists to refuse, so there is no update path and no override flag. An estate that is genuinely a
 * different estate has a different database.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function claimEstateIdentity(
  sql: Db,
  environment: Environment,
  claimedBy: string,
): Promise<{ environment: Environment; claimedAt: string; claimed: boolean }> {
  const existing = await readEstateIdentity(sql)
  if (existing) {
    // ── THE BOOT REFUSAL. A compose file pointed at the wrong environment is a container that
    //    will not start, rather than a restore into the wrong estate six weeks later. `index.ts`
    //    calls this at boot precisely so the failure is loud and early.
    if (existing.environment !== environment) {
      throw new BackupError(
        `this database was claimed by the ${existing.environment} estate but this process is ` +
          `configured as ${environment} — refusing to start. One of the two is pointed at the ` +
          `wrong estate, and continuing would let a backup be labelled with the wrong environment.`,
      )
    }
    return { ...existing, claimed: false }
  }

  const rows = await sql<{ environment: string; claimed_at: Date }[]>`
    insert into estate_identity (singleton, environment, claimed_by)
    values (true, ${environment}, ${claimedBy})
    on conflict (singleton) do nothing
    returning environment, claimed_at
  `
  const row = rows[0]
  if (!row) {
    // Another replica claimed it between the read and the insert. Re-read and re-check rather than
    // assuming agreement: if that replica claimed a different environment we must still refuse.
    const settled = await readEstateIdentity(sql)
    if (!settled) throw new BackupError('the estate identity could not be claimed or read')
    if (settled.environment !== environment) {
      throw new BackupError(
        `this database was claimed by the ${settled.environment} estate but this process is ` +
          `configured as ${environment} — refusing to start`,
      )
    }
    return { ...settled, claimed: false }
  }
  return {
    environment: row.environment as Environment,
    claimedAt: row.claimed_at.toISOString(),
    claimed: true,
  }
}

export async function readEstateIdentity(
  sql: Db,
): Promise<{ environment: Environment; claimedAt: string } | null> {
  const rows = await sql<{ environment: string; claimed_at: Date }[]>`
    select environment, claimed_at from estate_identity where singleton
  `
  const row = rows[0]
  if (!row) return null
  return { environment: row.environment as Environment, claimedAt: row.claimed_at.toISOString() }
}

/* ---------------------------------------------------------------------------------- settings */

export interface BackupSettings {
  readonly rootPath: string
  readonly retentionCopies: number
  readonly ceilingBytes: bigint
  readonly minFreeBytes: bigint
  readonly scheduleEnabled: boolean
  readonly scheduleEveryMinutes: number
  readonly verifyEnabled: boolean
  readonly verifyEveryMinutes: number
  readonly updatedAt: string
  readonly updatedBy: string
}

/**
 * The bounds the schema enforces, served so a console renders the range an operator is choosing
 * inside rather than discovering it as a 400. The same numbers as migration 10's CHECKs — and they
 * are read from one place here so a console and the database cannot disagree about them.
 */
export const CEILINGS = Object.freeze({
  retentionCopies: Object.freeze({ min: 1, max: 365 }),
  ceilingBytes: Object.freeze({ min: 1_073_741_824n, max: 1_099_511_627_776n }),
  minFreeBytes: Object.freeze({ min: 1_073_741_824n, max: 1_099_511_627_776n }),
  scheduleEveryMinutes: Object.freeze({ min: 15, max: 43_200 }),
  verifyEveryMinutes: Object.freeze({ min: 60, max: 43_200 }),
})

interface SettingsRow {
  readonly root_path: string
  readonly retention_copies: number
  readonly ceiling_bytes: string
  readonly min_free_bytes: string
  readonly schedule_enabled: boolean
  readonly schedule_every_minutes: number
  readonly verify_enabled: boolean
  readonly verify_every_minutes: number
  readonly updated_at: Date
  readonly updated_by: string
}

function toSettings(row: SettingsRow): BackupSettings {
  return {
    rootPath: row.root_path,
    retentionCopies: row.retention_copies,
    ceilingBytes: BigInt(row.ceiling_bytes),
    minFreeBytes: BigInt(row.min_free_bytes),
    scheduleEnabled: row.schedule_enabled,
    scheduleEveryMinutes: row.schedule_every_minutes,
    verifyEnabled: row.verify_enabled,
    verifyEveryMinutes: row.verify_every_minutes,
    updatedAt: row.updated_at.toISOString(),
    updatedBy: row.updated_by,
  }
}

export async function readSettings(sql: Db): Promise<BackupSettings> {
  const rows = await sql<SettingsRow[]>`
    select root_path, retention_copies, ceiling_bytes, min_free_bytes, schedule_enabled,
           schedule_every_minutes, verify_enabled, verify_every_minutes, updated_at, updated_by
      from backup_settings where singleton
  `
  const row = rows[0]
  if (!row) throw new BackupError('backup settings are missing — migration 10 seeds exactly one row')
  return toSettings(row)
}

/**
 * A destination path an operator may set.
 *
 * Validated here AND by `backup_settings_root_is_absolute` in the schema, because this string
 * becomes a path in a process that runs `tar` and `pg_restore`. The schema constraint is the one
 * that holds when the write arrives by another door; this is the one that produces a sentence an
 * operator can act on.
 *
 * `..` is rejected outright rather than normalised. Normalising means deciding what the operator
 * meant, and a path traversal in a backup destination is a write primitive aimed anywhere on the
 * host — the one place where guessing is worse than refusing.
 */
export function assertRootPath(value: string): string {
  if (!value.startsWith('/')) throw new BackupError('the backup root must be an absolute path')
  if (value.includes('..')) throw new BackupError('the backup root may not contain ".."')
  if (!/^\/[A-Za-z0-9._/-]{0,255}$/.test(value)) {
    throw new BackupError(
      'the backup root may contain only letters, digits, dot, dash, underscore and slash',
    )
  }
  if (value.endsWith('/') && value.length > 1) {
    throw new BackupError('the backup root must not end in a slash')
  }
  return value
}

export interface SettingsChange {
  readonly rootPath?: string
  readonly retentionCopies?: number
  readonly ceilingBytes?: bigint
  readonly minFreeBytes?: bigint
  readonly scheduleEnabled?: boolean
  readonly scheduleEveryMinutes?: number
  readonly verifyEnabled?: boolean
  readonly verifyEveryMinutes?: number
}

export async function updateSettings(
  tx: Tx,
  change: SettingsChange,
  operator: string,
): Promise<BackupSettings> {
  if (change.rootPath !== undefined) assertRootPath(change.rootPath)

  const rows = await tx<SettingsRow[]>`
    update backup_settings set
      root_path              = coalesce(${change.rootPath ?? null}, root_path),
      retention_copies       = coalesce(${change.retentionCopies ?? null}, retention_copies),
      ceiling_bytes          = coalesce(${change.ceilingBytes?.toString() ?? null}::bigint, ceiling_bytes),
      min_free_bytes         = coalesce(${change.minFreeBytes?.toString() ?? null}::bigint, min_free_bytes),
      schedule_enabled       = coalesce(${change.scheduleEnabled ?? null}, schedule_enabled),
      schedule_every_minutes = coalesce(${change.scheduleEveryMinutes ?? null}, schedule_every_minutes),
      verify_enabled         = coalesce(${change.verifyEnabled ?? null}, verify_enabled),
      verify_every_minutes   = coalesce(${change.verifyEveryMinutes ?? null}, verify_every_minutes),
      updated_at             = now(),
      updated_by             = ${operator}
     where singleton
    returning root_path, retention_copies, ceiling_bytes, min_free_bytes, schedule_enabled,
              schedule_every_minutes, verify_enabled, verify_every_minutes, updated_at, updated_by
  `
  const row = rows[0]
  if (!row) throw new BackupError('backup settings are missing')
  return toSettings(row)
}

/* -------------------------------------------------------------------------------- backup runs */

export interface BackupRun {
  readonly id: string
  readonly environment: Environment
  readonly composeProject: string
  readonly kind: BackupKind
  readonly state: BackupState
  readonly requestedBy: string
  readonly reason: string | null
  readonly rootPath: string
  readonly directory: string | null
  readonly queuedAt: string
  readonly startedAt: string | null
  readonly finishedAt: string | null
  readonly totalBytes: bigint | null
  readonly artefactCount: number | null
  readonly manifestSha256: string | null
  readonly clusterSystemId: string | null
  readonly includesCustody: boolean
  readonly error: string | null
  readonly verifiedAt: string | null
  readonly verifiedByRestore: string | null
}

interface BackupRunRow {
  readonly id: string
  readonly environment: string
  readonly compose_project: string
  readonly kind: string
  readonly state: string
  readonly requested_by: string
  readonly reason: string | null
  readonly root_path: string
  readonly directory: string | null
  readonly queued_at: Date
  readonly started_at: Date | null
  readonly finished_at: Date | null
  readonly total_bytes: string | null
  readonly artefact_count: number | null
  readonly manifest_sha256: string | null
  readonly cluster_system_id: string | null
  readonly includes_custody: boolean
  readonly error: string | null
  readonly verified_at: Date | null
  readonly verified_by_restore: string | null
}

function toBackupRun(row: BackupRunRow): BackupRun {
  return {
    id: row.id,
    environment: row.environment as Environment,
    composeProject: row.compose_project,
    kind: row.kind as BackupKind,
    state: row.state as BackupState,
    requestedBy: row.requested_by,
    reason: row.reason,
    rootPath: row.root_path,
    directory: row.directory,
    queuedAt: row.queued_at.toISOString(),
    startedAt: row.started_at?.toISOString() ?? null,
    finishedAt: row.finished_at?.toISOString() ?? null,
    totalBytes: row.total_bytes === null ? null : BigInt(row.total_bytes),
    artefactCount: row.artefact_count,
    manifestSha256: row.manifest_sha256,
    clusterSystemId: row.cluster_system_id,
    includesCustody: row.includes_custody,
    error: row.error,
    verifiedAt: row.verified_at?.toISOString() ?? null,
    verifiedByRestore: row.verified_by_restore,
  }
}

const BACKUP_COLUMNS = `
  id, environment, compose_project, kind, state, requested_by, reason, root_path, directory,
  queued_at, started_at, finished_at, total_bytes, artefact_count, manifest_sha256,
  cluster_system_id, includes_custody, error, verified_at, verified_by_restore
`

export interface RequestBackupInput {
  readonly kind: BackupKind
  readonly requestedBy: string
  readonly reason: string | null
  readonly composeProject: string
  readonly correlationId: string | null
}

/**
 * Queue a backup.
 *
 * The environment is read from `estate_identity` rather than accepted, for the same reason a
 * restore's is: a label that can be passed can be passed wrongly, and this label is what a future
 * restore is checked against. A backup mislabelled at creation is a landmine that only goes off
 * during a recovery, which is the worst moment to discover it.
 */
export async function requestBackup(tx: Tx, input: RequestBackupInput): Promise<BackupRun> {
  const identity = await tx<{ environment: string }[]>`
    select environment from estate_identity where singleton
  `
  const environment = identity[0]?.environment
  if (!environment) {
    throw new BackupError(
      'this estate has not claimed an identity, so a backup cannot be labelled with an ' +
        'environment — and an unlabelled backup can be restored into the wrong estate',
    )
  }

  const settings = await tx<{ root_path: string }[]>`
    select root_path from backup_settings where singleton
  `
  const rootPath = settings[0]?.root_path
  if (!rootPath) throw new BackupError('backup settings are missing')

  const rows = await tx<BackupRunRow[]>`
    insert into backup_runs (environment, compose_project, kind, requested_by, reason, root_path,
                             correlation_id)
    values (${environment}, ${input.composeProject}, ${input.kind}, ${input.requestedBy},
            ${input.reason}, ${rootPath}, ${input.correlationId})
    returning ${tx.unsafe(BACKUP_COLUMNS)}
  `
  const row = rows[0]
  if (!row) throw new BackupError('the backup run could not be queued')
  return toBackupRun(row)
}

export interface BackupQuery {
  readonly state?: BackupState
  readonly limit?: number
}

export async function listBackups(sql: Db, query: BackupQuery = {}): Promise<readonly BackupRun[]> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), 200)
  const rows = await sql<BackupRunRow[]>`
    select ${sql.unsafe(BACKUP_COLUMNS)}
      from backup_runs
     where true
       ${query.state ? sql`and state = ${query.state}` : sql``}
     order by queued_at desc
     limit ${limit}
  `
  return rows.map(toBackupRun)
}

export async function findBackup(sql: Db, id: string): Promise<BackupRun | null> {
  const rows = await sql<BackupRunRow[]>`
    select ${sql.unsafe(BACKUP_COLUMNS)} from backup_runs where id = ${id}
  `
  const row = rows[0]
  return row ? toBackupRun(row) : null
}

export interface BackupArtefact {
  readonly id: string
  readonly kind: 'database' | 'vault' | 'files'
  readonly name: string
  readonly relPath: string
  readonly bytes: bigint
  readonly sha256: string
  readonly entryCount: bigint | null
}

export async function listArtefacts(sql: Db, runId: string): Promise<readonly BackupArtefact[]> {
  const rows = await sql<
    {
      id: string
      kind: string
      name: string
      rel_path: string
      bytes: string
      sha256: string
      entry_count: string | null
    }[]
  >`
    select id, kind, name, rel_path, bytes, sha256, entry_count
      from backup_artefacts where run_id = ${runId} order by kind, name
  `
  return rows.map((row) => ({
    id: row.id,
    kind: row.kind as BackupArtefact['kind'],
    name: row.name,
    relPath: row.rel_path,
    bytes: BigInt(row.bytes),
    sha256: row.sha256,
    entryCount: row.entry_count === null ? null : BigInt(row.entry_count),
  }))
}

/* ------------------------------------------------------------------------------- restore runs */

export interface RestoreRun {
  readonly id: string
  readonly backupRunId: string
  readonly environment: Environment
  readonly mode: RestoreMode
  readonly targets: readonly string[]
  readonly state: RestoreState
  readonly requestedBy: string
  readonly reason: string | null
  readonly approvalId: string | null
  readonly queuedAt: string
  readonly startedAt: string | null
  readonly finishedAt: string | null
  readonly artefactEnvironment: string | null
  readonly checksumsVerified: boolean | null
  readonly outcome: Record<string, unknown>
  readonly error: string | null
}

interface RestoreRunRow {
  readonly id: string
  readonly backup_run_id: string
  readonly environment: string
  readonly mode: string
  readonly targets: unknown
  readonly state: string
  readonly requested_by: string
  readonly reason: string | null
  readonly approval_id: string | null
  readonly queued_at: Date
  readonly started_at: Date | null
  readonly finished_at: Date | null
  readonly artefact_environment: string | null
  readonly checksums_verified: boolean | null
  readonly outcome: Record<string, unknown>
  readonly error: string | null
}

function toRestoreRun(row: RestoreRunRow): RestoreRun {
  return {
    id: row.id,
    backupRunId: row.backup_run_id,
    environment: row.environment as Environment,
    mode: row.mode as RestoreMode,
    targets: Array.isArray(row.targets) ? (row.targets as string[]) : [],
    state: row.state as RestoreState,
    requestedBy: row.requested_by,
    reason: row.reason,
    approvalId: row.approval_id,
    queuedAt: row.queued_at.toISOString(),
    startedAt: row.started_at?.toISOString() ?? null,
    finishedAt: row.finished_at?.toISOString() ?? null,
    artefactEnvironment: row.artefact_environment,
    checksumsVerified: row.checksums_verified,
    outcome: row.outcome ?? {},
    error: row.error,
  }
}

const RESTORE_COLUMNS = `
  id, backup_run_id, environment, mode, targets, state, requested_by, reason, approval_id,
  queued_at, started_at, finished_at, artefact_environment, checksums_verified, outcome, error
`

/**
 * The exact phrase an operator must type to authorise a LIVE restore.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **IT NAMES WHAT, FROM WHEN, AND INTO WHICH ENVIRONMENT — because those are the three things an
 * operator gets wrong at three in the morning.**
 *
 * A confirmation that is merely "type RESTORE" proves the operator can read one word. This one
 * cannot be typed correctly unless they have looked at which backup they selected and which estate
 * they are pointed at. It is deliberately not copy-pasteable from a single UI element: the
 * environment and the timestamp are rendered apart from each other on the page.
 *
 * Second-granularity, UTC, `Z`-suffixed. Millisecond precision would make the phrase impossible to
 * transcribe from a rendered timestamp, and a confirmation nobody can type is a confirmation that
 * gets pasted from the error message.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function expectedConfirmation(backup: Pick<BackupRun, 'environment' | 'queuedAt'>): string {
  const at = new Date(backup.queuedAt)
  const stamp = `${at.toISOString().slice(0, 19)}Z`
  return `restore ${backup.environment} from ${stamp}`
}

export interface RequestRestoreInput {
  readonly backupRunId: string
  readonly mode: RestoreMode
  readonly targets: readonly string[]
  readonly requestedBy: string
  readonly reason: string | null
  readonly approvalId: string | null
  readonly confirmation: string | null
  readonly correlationId: string | null
}

/**
 * Queue a restore.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THERE ARE FOUR INDEPENDENT GATES AND THIS FUNCTION IS ONLY THE FIRST.**
 *
 *   1. HERE — the typed confirmation must match exactly, and a live restore must name an approval.
 *      Produces a sentence an operator can act on.
 *   2. `restore_runs_environment_matches()`, migration 10 — copies the environment off the BACKUP
 *      rather than the request, refuses a cross-environment restore, refuses an approval that is
 *      not approved or names a different backup, refuses a backup that did not succeed. In the
 *      schema, so it holds against a caller with a psql prompt.
 *   3. `restore_runs_live_is_confirmed`, a CHECK — a live row cannot exist without both an
 *      approval id and a confirmation string.
 *   4. The RUNNER, in `deploy/backup` — re-reads the environment out of the artefact's own
 *      `MANIFEST.json` on disk and refuses on mismatch before touching a byte. This is the gate
 *      that still works when the database being restored INTO is the one that was lost.
 *
 * Four gates for one decision is not belt-and-braces theatre. Gate 2 protects against a route
 * rewrite, gate 3 against a direct write, and gate 4 against this entire service being unavailable
 * — which, during the disaster a restore exists for, is the likely case.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function requestRestore(tx: Tx, input: RequestRestoreInput): Promise<RestoreRun> {
  const backups = await tx<BackupRunRow[]>`
    select ${tx.unsafe(BACKUP_COLUMNS)} from backup_runs where id = ${input.backupRunId}
  `
  const backupRow = backups[0]
  if (!backupRow) throw new BackupError(`no backup run ${input.backupRunId}`)
  const backup = toBackupRun(backupRow)

  // Read rather than trust: the estate's own identity, for the message. The refusal of record is
  // the schema trigger; this produces the readable version of it before the insert.
  const identity = await tx<{ environment: string }[]>`
    select environment from estate_identity where singleton
  `
  const estateEnvironment = identity[0]?.environment
  if (!estateEnvironment) {
    throw new BackupError(
      'this estate has not claimed an identity, so a restore cannot be checked for environment ' +
        'confusion — refusing',
    )
  }
  if (backup.environment !== estateEnvironment) {
    throw new EnvironmentMismatchError(backup.environment, estateEnvironment)
  }

  if (backup.state !== 'succeeded') {
    throw new BackupError(
      `backup ${backup.id} is in state ${backup.state}, not succeeded — restoring from an ` +
        'incomplete set half-overwrites live data, which is worse than not restoring',
    )
  }

  if (input.mode === 'live') {
    if (!input.approvalId) {
      throw new BackupError(
        'a live restore overwrites live data and needs an approved two-operator estate.restore ' +
          'approval — raise one through POST /v1/approvals first',
      )
    }
    const expected = expectedConfirmation(backup)
    if (input.confirmation !== expected) {
      // The expected phrase IS returned, deliberately. It is not a secret — it is derived from two
      // values already on the operator's screen — and withholding it would make a legitimate
      // operator guess at punctuation during an incident. What it is not is a one-click bypass:
      // typing it still requires having read it, and the approval gate is untouched by it.
      throw new BackupError(
        `the confirmation phrase must be exactly "${expected}" — it names what is being restored, ` +
          'from when, and into which environment',
      )
    }
  }

  // ── ONE RESTORE AT A TIME, ACROSS THE WHOLE ESTATE.
  //
  // Two concurrent restores are two processes dropping and recreating the same databases, and the
  // winner is decided by scheduling. Serialising them is not an optimisation: a `verify` restore
  // that overlaps a `live` one would also make the verification report on a database that was being
  // rewritten underneath it, which is a PASS that means nothing.
  //
  // Refused loudly rather than queued. A restore that silently waits is a restore an operator
  // believes has already happened.
  const inflight = await tx<{ id: string; mode: string; state: string }[]>`
    select id, mode, state from restore_runs
     where state in ('queued','running') order by queued_at limit 1
  `
  const busy = inflight[0]
  if (busy) {
    throw new BackupError(
      `a ${busy.mode} restore (${busy.id}) is already ${busy.state} — only one restore may run at ` +
        'a time, because two would be two processes rewriting the same databases',
    )
  }

  const rows = await tx<RestoreRunRow[]>`
    insert into restore_runs (backup_run_id, environment, mode, targets, requested_by, reason,
                              approval_id, confirmation, correlation_id)
    values (${input.backupRunId}, ${backup.environment}, ${input.mode},
            ${tx.json([...input.targets] as unknown as Record<string, never>)},
            ${input.requestedBy}, ${input.reason}, ${input.approvalId}, ${input.confirmation},
            ${input.correlationId})
    returning ${tx.unsafe(RESTORE_COLUMNS)}
  `
  const row = rows[0]
  if (!row) throw new BackupError('the restore run could not be queued')
  return toRestoreRun(row)
}

export async function listRestores(sql: Db, limit = 50): Promise<readonly RestoreRun[]> {
  const capped = Math.min(Math.max(limit, 1), 200)
  const rows = await sql<RestoreRunRow[]>`
    select ${sql.unsafe(RESTORE_COLUMNS)} from restore_runs order by queued_at desc limit ${capped}
  `
  return rows.map(toRestoreRun)
}

export async function listRestoresFor(sql: Db, backupRunId: string): Promise<readonly RestoreRun[]> {
  const rows = await sql<RestoreRunRow[]>`
    select ${sql.unsafe(RESTORE_COLUMNS)} from restore_runs
     where backup_run_id = ${backupRunId} order by queued_at desc
  `
  return rows.map(toRestoreRun)
}

/* --------------------------------------------------------------------------- handing off work */

/**
 * Put a `backup.*` job in the queue, inside the caller's transaction.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE INSERT IS RAW SQL RATHER THAN `JobQueue.enqueue`, AND THAT IS THE POINT.**
 *
 * `JobQueue` holds its own connection. Enqueueing through it would commit the job independently of
 * the row it refers to, which breaks in both directions: a rolled-back restore request would leave
 * a job pointing at a row that does not exist, and a committed restore row whose enqueue failed
 * would sit `queued` for ever with nothing coming to claim it. Both are silent. So the job and the
 * domain row commit together, in one transaction, exactly as `appendAudit` requires of an audit row
 * and the change it describes.
 *
 * **THE KEY IS THE RUN ID, NOT THE RESOURCE, AND THAT IS THE EXCEPTION TO `jobs.ts`'s RULE.**
 * Everywhere else in this service the lease key names the contended resource, because the work is
 * recurring and N enqueues must collapse to one run. Here each row is a distinct, operator-
 * requested artefact: collapsing two backup requests into one would silently discard the second,
 * and `(kind, key)` unique would do exactly that under `onConflict: 'keep'`. The contention that
 * genuinely exists — never two restores at once — is enforced above by refusing a second request,
 * and by running the data plane at concurrency 1.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function enqueueBackupJob(
  tx: Tx,
  kind: typeof BACKUP_RUN | typeof BACKUP_RESTORE | typeof BACKUP_VERIFY | typeof BACKUP_PRUNE,
  key: string,
  payload: Record<string, unknown>,
): Promise<void> {
  await tx`
    insert into jobs (kind, key, payload, max_attempts)
    values (${kind}, ${key}, ${tx.json(payload as Record<string, never>)},
            ${kind === BACKUP_RESTORE ? 1 : 3})
    on conflict (kind, key) do nothing
  `
}

/**
 * `max_attempts` is 1 for a restore and 3 for everything else, deliberately.
 *
 * A failed backup is safe to retry: the worst case is a wasted dump. A failed LIVE restore is not —
 * it may have already dropped the target database, so an automatic second attempt would run against
 * a half-restored estate with no operator watching. A restore that fails stops and waits for a
 * human, which is the only correct behaviour for a job that overwrites money data.
 */
export const RESTORE_MAX_ATTEMPTS = 1

/* ----------------------------------------------------------------------------- what this buys */

export interface Protection {
  readonly destinationDevice: string
  readonly sameHost: boolean
  readonly covers: readonly string[]
  readonly doesNotCover: readonly string[]
  readonly custodyKeyringIncluded: false
  readonly custodyKeyringNote: string
  /** What is written to the backup disk. Ciphertext and data — never a secret in the clear. */
  readonly onBackupDisk: readonly string[]
  /**
   * What must live OFF this machine, and without which parts of a backup set cannot be opened.
   *
   * This list is the separation rule made visible. Every item on it, if it were moved onto the
   * backup disk, would turn an encrypted artefact into a portable copy of the coins.
   */
  readonly mustLeaveTheMachine: readonly string[]
}

/**
 * What a backup on this estate actually protects against, stated so the console cannot imply more.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A SECOND DISK IN THE SAME ROOM IS A SECOND DISK IN THE SAME ROOM.**
 *
 * The estate's databases live on `/dev/sda2`; backups are written to `/dev/sdb1`, a genuinely
 * separate physical device. That closes the gap the custody rehearsal named — "backups currently
 * sit on the same disk as the thing they back up" — and it closes NOTHING ELSE. The server and its
 * backups are still one machine, in one building, on one power feed, reachable by one `rm -rf`.
 *
 * This is served to the console as two lists rather than a status, because a status invites a
 * green tick and a green tick is a claim. An operator who believes they have off-site backups and
 * does not is in a worse position than one who knows they have none: the first will not act.
 *
 * The honest remedy for everything in `doesNotCover` is an off-host copy, which this estate does
 * not have — no NAS, no object store, and no `rclone`/`restic`/`borg` installed. That is reported
 * rather than papered over.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function protectionFor(settings: BackupSettings): Protection {
  return {
    destinationDevice: settings.rootPath,
    sameHost: true,
    covers: Object.freeze([
      'Failure of the disk holding the databases — backups are written to a second physical device.',
      'Accidental DROP, a bad migration, or a service corrupting its own data.',
      'A restore rehearsal, because verifying into a scratch database costs nothing and is safe.',
    ]),
    doesNotCover: Object.freeze([
      'Loss of the machine — theft, fire, flood or a dead motherboard takes the backups with it.',
      'Ransomware or a malicious operator: a process that can write the databases can also reach /data.',
      'An `rm -rf` on this host, which removes both copies in one command.',
      'Any off-site retention whatsoever. There is no NAS, no object store and no cloud target configured.',
    ]),
    custodyKeyringIncluded: false,
    custodyKeyringNote:
      'Custody backups contain the encrypted vault only. The key-encryption keyring ' +
      '(CUSTODY_MASTER_SECRET_V<n>) is deliberately NOT in any backup and never will be: the vault ' +
      'and the keyring on one medium is not an encrypted backup, it is a plaintext key store with ' +
      'extra steps. The keyring is backed up by the physical, off-site procedure in ' +
      'deploy/docs/custody-backup-restore.md §4, which is the owner’s to perform and no script’s.',
    onBackupDisk: Object.freeze([
      'Every service database, as a pg_dump custom-format archive.',
      'The custody vault — encrypted blobs only, directory names intact.',
      'The miner coinbase keys, ENCRYPTED to an offline recipient before they are written.',
      'File state: the Tessera sprite set and the studio assets.',
      'A MANIFEST.json carrying a SHA-256 per artefact and the environment this estate is.',
    ]),
    mustLeaveTheMachine: Object.freeze([
      'The custody keyring (CUSTODY_MASTER_SECRET_V<n>) — paper and an encrypted USB, two ' +
        'buildings, per custody-backup-restore.md §4. Without it the vault backup is ciphertext ' +
        'and nothing else, which is exactly what it should be to anyone who steals the disk.',
      'The age identity that opens the miner-key artefact. Its PUBLIC half lives on this host so ' +
        'backups can be written; its private half must never be here, or the host holds both the ' +
        'lock and the key and the encryption has bought nothing.',
    ]),
  }
}

/* ------------------------------------------------------------------------------- wire shapes */

/** `bigint` is not a JSON number, so every size crosses the wire as a decimal string. */
export function backupToJson(run: BackupRun): Record<string, unknown> {
  return {
    id: run.id,
    environment: run.environment,
    composeProject: run.composeProject,
    kind: run.kind,
    state: run.state,
    requestedBy: run.requestedBy,
    reason: run.reason,
    rootPath: run.rootPath,
    directory: run.directory,
    queuedAt: run.queuedAt,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    totalBytes: run.totalBytes?.toString() ?? null,
    artefactCount: run.artefactCount,
    manifestSha256: run.manifestSha256,
    clusterSystemId: run.clusterSystemId,
    includesCustody: run.includesCustody,
    error: run.error,
    verifiedAt: run.verifiedAt,
    verifiedByRestore: run.verifiedByRestore,
  }
}

export function artefactToJson(artefact: BackupArtefact): Record<string, unknown> {
  return {
    id: artefact.id,
    kind: artefact.kind,
    name: artefact.name,
    relPath: artefact.relPath,
    bytes: artefact.bytes.toString(),
    sha256: artefact.sha256,
    entryCount: artefact.entryCount?.toString() ?? null,
  }
}

export function restoreToJson(run: RestoreRun): Record<string, unknown> {
  return {
    id: run.id,
    backupRunId: run.backupRunId,
    environment: run.environment,
    mode: run.mode,
    targets: run.targets,
    state: run.state,
    requestedBy: run.requestedBy,
    reason: run.reason,
    approvalId: run.approvalId,
    queuedAt: run.queuedAt,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    artefactEnvironment: run.artefactEnvironment,
    checksumsVerified: run.checksumsVerified,
    outcome: run.outcome,
    error: run.error,
  }
}

export function settingsToJson(settings: BackupSettings): Record<string, unknown> {
  return {
    rootPath: settings.rootPath,
    retentionCopies: settings.retentionCopies,
    ceilingBytes: settings.ceilingBytes.toString(),
    minFreeBytes: settings.minFreeBytes.toString(),
    scheduleEnabled: settings.scheduleEnabled,
    scheduleEveryMinutes: settings.scheduleEveryMinutes,
    verifyEnabled: settings.verifyEnabled,
    verifyEveryMinutes: settings.verifyEveryMinutes,
    updatedAt: settings.updatedAt,
    updatedBy: settings.updatedBy,
  }
}
