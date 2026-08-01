/**
 * Feature flags, and operator broadcasts.
 *
 * ## Flags
 *
 * 17 §1 row 8: every backlog item ships with "a feature flag, with the default stated and the
 * owner named". Both are NOT NULL columns here rather than a convention, because 17 §9 records
 * what an unowned flag becomes: Crucible's performance fee is "complete, correct, well-designed
 * and earns nothing, because `CRUCIBLE_LIVE_ENABLED` defaults to `false`". A flag with an owner is
 * a flag somebody can be asked about.
 *
 * **A flag change is a privileged action and writes an audit row** — SD-15's Admin row lists
 * "every operator action, feature flag change, broadcast". It also emits an outbox event, because
 * a flag that this service knows about and the service behind it does not is a flag that does
 * nothing. This service does not enforce flags; it records them and announces the change.
 *
 * **A flag is not a kill switch and must not be used as one.** A kill switch is an emergency
 * freeze, SD-11 makes it asymmetric — set by one operator, cleared by two — and that asymmetry
 * cannot be expressed by a boolean anybody with the write scope can flip back. If an emergency
 * freeze lands here it goes through the approval queue, not through this table.
 *
 * ## Broadcasts
 *
 * 13 §11 routes scheduled maintenance to the public status page via "admin-api broadcasts", and
 * 13 §347 is emphatic that "the on-call operator writes them; nobody else publishes to the public
 * page". So a broadcast is created by a named operator, audited, and **retracted rather than
 * deleted** — "what did we tell users during the incident" is a question asked after the incident,
 * and a DELETE makes it unanswerable.
 */

import type { Sql, TransactionSql } from 'postgres'
import { appendAudit, type AuditRow } from './audit.ts'
import { emitOn } from './outbox.ts'

export type Db = Sql
export type Tx = TransactionSql

export class FlagError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FlagError'
  }
}

export interface FeatureFlag {
  readonly key: string
  readonly enabled: boolean
  readonly description: string
  readonly owner: string
  readonly createdAt: string
  readonly updatedAt: string
  readonly updatedBy: string
}

interface FlagRow {
  readonly key: string
  readonly enabled: boolean
  readonly description: string
  readonly owner: string
  readonly created_at: Date
  readonly updated_at: Date
  readonly updated_by: string
}

function toFlag(row: FlagRow): FeatureFlag {
  return {
    key: row.key,
    enabled: row.enabled,
    description: row.description,
    owner: row.owner,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    updatedBy: row.updated_by,
  }
}

export interface SetFlagInput {
  readonly key: string
  readonly enabled: boolean
  readonly description: string
  readonly owner: string
  /** `user:<uuid>`. Derived from the verified token. */
  readonly operator: string
  readonly correlationId?: string | null
}

/**
 * Create or update a flag, audit it, and announce it.
 *
 * The audit row records the value BEFORE and AFTER. "The flag is off" is not the useful fact six
 * months later; "it was on until 03:14 on the 12th, and this operator turned it off" is.
 */
export async function setFlag(
  tx: Tx,
  input: SetFlagInput,
  producer: string,
  now: () => Date = () => new Date(),
): Promise<{ flag: FeatureFlag; audit: AuditRow; changed: boolean }> {
  if (input.owner.trim().length === 0) {
    throw new FlagError('owner is required — a flag nobody owns is a flag nobody switches on')
  }
  if (input.description.trim().length === 0) {
    throw new FlagError('description is required — 17 §1 row 8 requires the default to be stated')
  }

  const before = await tx<FlagRow[]>`
    select key, enabled, description, owner, created_at, updated_at, updated_by
      from feature_flags where key = ${input.key} for update
  `
  const previous = before[0] ? toFlag(before[0]) : null

  const rows = await tx<FlagRow[]>`
    insert into feature_flags (key, enabled, description, owner, updated_at, updated_by)
    values (${input.key}, ${input.enabled}, ${input.description}, ${input.owner},
            ${now().toISOString()}::timestamptz, ${input.operator})
    on conflict (key) do update
       set enabled = excluded.enabled,
           description = excluded.description,
           owner = excluded.owner,
           updated_at = excluded.updated_at,
           updated_by = excluded.updated_by
    returning key, enabled, description, owner, created_at, updated_at, updated_by
  `
  const flag = toFlag(rows[0]!)
  const changed = previous === null || previous.enabled !== flag.enabled

  const audit = await appendAudit(
    tx,
    {
      actor: input.operator,
      action: previous === null ? 'admin.flag.created' : 'admin.flag.changed',
      subjectKind: 'feature_flag',
      subjectId: flag.key,
      outcome: 'allowed',
      correlationId: input.correlationId ?? null,
      payload: {
        before: previous ? { enabled: previous.enabled, owner: previous.owner } : null,
        after: { enabled: flag.enabled, owner: flag.owner },
        description: flag.description,
      },
    },
    now,
  )

  // Emitted whether or not the boolean moved: an owner change is a change somebody downstream may
  // care about, and a consumer deduping on the payload is cheaper than a producer guessing.
  await emitOn(tx, producer, {
    topic: 'admin.flag.changed',
    key: flag.key,
    actor: input.operator,
    ...(input.correlationId ? { correlationId: input.correlationId } : {}),
    payload: { key: flag.key, enabled: flag.enabled, owner: flag.owner, changed },
  })

  return { flag, audit, changed }
}

export async function listFlags(sql: Db): Promise<readonly FeatureFlag[]> {
  const rows = await sql<FlagRow[]>`
    select key, enabled, description, owner, created_at, updated_at, updated_by
      from feature_flags order by key
  `
  return rows.map(toFlag)
}

export async function findFlag(sql: Db | Tx, key: string): Promise<FeatureFlag | null> {
  const rows = await sql<FlagRow[]>`
    select key, enabled, description, owner, created_at, updated_at, updated_by
      from feature_flags where key = ${key}
  `
  const row = rows[0]
  return row ? toFlag(row) : null
}
