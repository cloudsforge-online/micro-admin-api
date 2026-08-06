/**
 * Operator broadcasts.
 *
 * 13-operational-model.md routes "scheduled maintenance" to the public status page as
 * "`admin-api` broadcasts", and :347 is emphatic that "the on-call operator writes them; nobody
 * else publishes to the public page".
 *
 * **A retraction is a state, never a DELETE.** "What did we tell users during the incident, and
 * when did we stop saying it" is a question asked during the post-incident review, and a DELETE
 * makes it unanswerable. `retracted_at` and `retracted_by` are constrained to move together, so a
 * retraction that names nobody cannot be written down.
 *
 * **A broadcast is not a notification.** It is an unaddressed statement on a public page. Nothing
 * here holds a `user_id`, has a read state, or honours a preference — those are notify's, and
 * 12 §SD-15 keeps the two apart deliberately: a `critical` security notification is delivered
 * despite preferences (17 §7 row 8), and that decision belongs to the service that knows who the
 * message is for. This one does not know, and must not learn.
 */

import type { Sql, TransactionSql } from 'postgres'
import { appendAudit, type AuditRow } from './audit.ts'
import { emitOn } from './outbox.ts'

export type Db = Sql
export type Tx = TransactionSql

export type Severity = 'info' | 'maintenance' | 'incident'

export const SEVERITIES: readonly Severity[] = Object.freeze(['info', 'maintenance', 'incident'])

export class BroadcastError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BroadcastError'
  }
}

export class BroadcastNotFoundError extends BroadcastError {
  constructor(id: string) {
    super(`no broadcast ${id}`)
    this.name = 'BroadcastNotFoundError'
  }
}

export interface Broadcast {
  readonly id: string
  readonly severity: Severity
  readonly title: string
  readonly body: string
  readonly startsAt: string
  readonly endsAt: string | null
  readonly publishedBy: string
  readonly publishedAt: string
  readonly retractedAt: string | null
  readonly retractedBy: string | null
}

interface BroadcastRow {
  readonly id: string
  readonly severity: Severity
  readonly title: string
  readonly body: string
  readonly starts_at: Date
  readonly ends_at: Date | null
  readonly published_by: string
  readonly published_at: Date
  readonly retracted_at: Date | null
  readonly retracted_by: string | null
}

const COLUMNS = `id, severity, title, body, starts_at, ends_at, published_by, published_at,
                 retracted_at, retracted_by`

function toBroadcast(row: BroadcastRow): Broadcast {
  return {
    id: row.id,
    severity: row.severity,
    title: row.title,
    body: row.body,
    startsAt: row.starts_at.toISOString(),
    endsAt: row.ends_at?.toISOString() ?? null,
    publishedBy: row.published_by,
    publishedAt: row.published_at.toISOString(),
    retractedAt: row.retracted_at?.toISOString() ?? null,
    retractedBy: row.retracted_by,
  }
}

export interface PublishInput {
  readonly severity: Severity
  readonly title: string
  readonly body: string
  readonly startsAt?: Date
  readonly endsAt?: Date | null
  /** `user:<uuid>`. Derived from the verified token. */
  readonly operator: string
  readonly correlationId?: string | null
}

export async function publishBroadcast(
  tx: Tx,
  input: PublishInput,
  producer: string,
  now: () => Date = () => new Date(),
): Promise<{ broadcast: Broadcast; audit: AuditRow }> {
  if (!SEVERITIES.includes(input.severity)) {
    throw new BroadcastError(`severity must be one of ${SEVERITIES.join(', ')}`)
  }
  const startsAt = input.startsAt ?? now()
  if (input.endsAt && input.endsAt.getTime() <= startsAt.getTime()) {
    throw new BroadcastError('endsAt must be after startsAt')
  }

  const rows = await tx<BroadcastRow[]>`
    insert into broadcasts (severity, title, body, starts_at, ends_at, published_by, published_at)
    values (${input.severity}, ${input.title}, ${input.body},
            ${startsAt.toISOString()}::timestamptz,
            ${input.endsAt ? input.endsAt.toISOString() : null}::timestamptz,
            ${input.operator}, ${now().toISOString()}::timestamptz)
    returning ${tx.unsafe(COLUMNS)}
  `
  const broadcast = toBroadcast(rows[0]!)

  const audit = await appendAudit(
    tx,
    {
      actor: input.operator,
      action: 'admin.broadcast.published',
      subjectKind: 'broadcast',
      subjectId: broadcast.id,
      outcome: 'allowed',
      correlationId: input.correlationId ?? null,
      payload: {
        severity: broadcast.severity,
        title: broadcast.title,
        startsAt: broadcast.startsAt,
        endsAt: broadcast.endsAt,
      },
    },
    now,
  )

  await emitOn(tx, producer, {
    topic: 'admin.broadcast.published',
    key: broadcast.id,
    actor: input.operator,
    ...(input.correlationId ? { correlationId: input.correlationId } : {}),
    payload: {
      id: broadcast.id,
      severity: broadcast.severity,
      title: broadcast.title,
      body: broadcast.body,
      startsAt: broadcast.startsAt,
      endsAt: broadcast.endsAt,
    },
  })

  return { broadcast, audit }
}

export async function retractBroadcast(
  tx: Tx,
  id: string,
  operator: string,
  correlationId: string | null,
  producer: string,
  now: () => Date = () => new Date(),
): Promise<{ broadcast: Broadcast; audit: AuditRow }> {
  const rows = await tx<BroadcastRow[]>`
    update broadcasts
       set retracted_at = ${now().toISOString()}::timestamptz, retracted_by = ${operator}
     where id = ${id} and retracted_at is null
    returning ${tx.unsafe(COLUMNS)}
  `
  const row = rows[0]
  if (!row) {
    const existing = await tx<{ id: string }[]>`select id from broadcasts where id = ${id}`
    // A second retraction claims no row. That is not an error the operator needs to see as a
    // failure — the broadcast is retracted either way — but it must not write a second audit row
    // saying it happened twice.
    throw existing.length > 0
      ? new BroadcastError(`broadcast ${id} is already retracted`)
      : new BroadcastNotFoundError(id)
  }
  const broadcast = toBroadcast(row)

  const audit = await appendAudit(
    tx,
    {
      actor: operator,
      action: 'admin.broadcast.retracted',
      subjectKind: 'broadcast',
      subjectId: broadcast.id,
      outcome: 'allowed',
      correlationId,
      payload: { severity: broadcast.severity, title: broadcast.title, publishedBy: broadcast.publishedBy },
    },
    now,
  )

  await emitOn(tx, producer, {
    topic: 'admin.broadcast.retracted',
    key: broadcast.id,
    actor: operator,
    ...(correlationId ? { correlationId } : {}),
    payload: { id: broadcast.id, retractedBy: operator },
  })

  return { broadcast, audit }
}

export interface BroadcastQuery {
  /** Only those live at this instant: started, not ended, not retracted. */
  readonly liveAt?: Date
  readonly limit?: number
}

export async function listBroadcasts(sql: Db, query: BroadcastQuery = {}): Promise<readonly Broadcast[]> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), 200)
  const at = query.liveAt?.toISOString() ?? null
  const rows = await sql<BroadcastRow[]>`
    select ${sql.unsafe(COLUMNS)} from broadcasts
     where true
       ${
         at
           ? sql`and retracted_at is null
                 and starts_at <= ${at}::timestamptz
                 and (ends_at is null or ends_at > ${at}::timestamptz)`
           : sql``
       }
     order by published_at desc
     limit ${limit}
  `
  return rows.map(toBroadcast)
}
