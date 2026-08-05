/**
 * The tamper-evident audit log.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT "TAMPER-EVIDENT" MEANS HERE, PRECISELY, AND WHAT IT DOES NOT MEAN.**
 *
 * Each row commits to its predecessor: `hash = H(prev_hash ‖ every other column)`. That gives
 * three properties, and it is worth being exact about which is which, because a claim of
 * tamper-evidence that overstates itself is worse than none.
 *
 *   **An edit is detected.** Change any hashed field of row N and `H(row N)` no longer equals the
 *   stored hash, and no longer equals row N+1's `prev_hash`. Two independent failures.
 *
 *   **An interior deletion is detected.** Remove row N and row N+1's `prev_hash` names a hash
 *   that is not the hash of the row before it. The chain is broken at exactly the gap.
 *
 *   **A truncation is detected only against a checkpoint.** Remove the LAST N rows and what is
 *   left is a shorter chain that verifies perfectly — this is the attack somebody covering their
 *   tracks would actually run, because it needs no forgery. `audit_chain_checkpoints` is the
 *   answer: the verification job records "the chain reached seq S with head H and N events", so a
 *   truncation below a checkpoint names a row that is no longer there. An attacker who can also
 *   delete the checkpoint defeats it; the point is that they now have to alter two tables
 *   consistently, and the checkpoint is the row a backup and an external attestation carry.
 *
 * What none of this survives is an attacker who can rewrite the whole table and recompute every
 * hash. Nothing stored in the same database as the data it attests can. The chain raises the cost
 * from "one UPDATE" to "recompute every row after the one you changed, in one transaction,
 * without the nightly verifier running in between" — and SD-16 runs that verifier nightly and
 * calls a break a P0.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **AN OPERATOR ACTS AS THEMSELVES.** `actor` is a principal — `user:<uuid>` or `service:<name>`
 * — and there is no route on this service that lets a caller supply one. It is derived from the
 * verified bearer token, always. The frozen estate's `/internal` routes took a `userId` as a
 * parameter, which is an act-as-anyone primitive: `deploy/gateway/dynamic/policy.yml` refuses
 * them from outside for exactly that reason. Where an action is taken on a user's behalf, the
 * user is the SUBJECT (`subject_kind = 'user'`) and the operator is the ACTOR. The two are
 * different columns because they are different facts, and conflating them is how an audit log
 * comes to say that a customer revoked their own entitlement.
 *
 * **APPENDS ARE SERIALISED, AND THEN THE DATABASE SERIALISES THEM AGAIN.** `pg_advisory_xact_lock`
 * makes concurrent appenders queue rather than race; `audit_events_chain_uniq` makes a fork
 * unrepresentable even if a future appender forgets the lock. Belt and braces on the one table
 * where a silent fork would be indistinguishable from a working system.
 */

import { createHash } from 'node:crypto'
import { ERASABLE_SUBJECT_KIND, RESTRICTED_SUBJECT, erasedSubjects } from './erasure.ts'
import type { Sql, TransactionSql } from 'postgres'

export type Db = Sql
export type Tx = TransactionSql

/** The predecessor of the first row. A literal, so a chain of length one still has a link. */
export const GENESIS_HASH = 'genesis:admin-api:v1'

/**
 * The advisory lock every append takes.
 *
 * Transaction-scoped, so it is released by COMMIT or ROLLBACK and a crashed appender cannot wedge
 * the audit log — which would stop every privileged action in the estate, since none of them may
 * commit without their audit row.
 */
export const CHAIN_LOCK_KEY = 8_140_251_099_723_001n

export type AuditOutcome = 'allowed' | 'refused' | 'failed'

export interface AuditInput {
  /** `user:<uuid>` or `service:<name>`. Derived from the token; never supplied by a caller. */
  readonly actor: string
  /** `<service>.<aggregate>.<past-tense-verb>`, e.g. `admin.approval.granted`. */
  readonly action: string
  readonly subjectKind: string
  readonly subjectId: string
  readonly outcome: AuditOutcome
  readonly reasonCode?: string | null
  readonly correlationId?: string | null
  readonly payload?: Record<string, unknown>
  /** The service that originally recorded this. Defaults to this one. */
  readonly source?: string
  /** Set only for a mirrored row. Unique, and the dedupe key for at-least-once delivery. */
  readonly sourceEventId?: string | null
  /** The source's own clock for a mirrored row; this process's for a local one. */
  readonly occurredAt?: Date
}

export interface AuditRow {
  readonly seq: bigint
  readonly id: string
  readonly occurredAt: string
  readonly recordedAt: string
  readonly actor: string
  readonly action: string
  readonly subjectKind: string
  readonly subjectId: string
  readonly reasonCode: string | null
  readonly outcome: AuditOutcome
  readonly source: string
  readonly sourceEventId: string | null
  readonly correlationId: string | null
  readonly payload: Record<string, unknown>
  readonly prevHash: string
  readonly hash: string
}

/** The exact set of fields the hash covers, in the exact order it covers them. */
export interface HashableAuditRow {
  readonly seq: bigint
  readonly id: string
  readonly occurredAt: string
  readonly recordedAt: string
  readonly actor: string
  readonly action: string
  readonly subjectKind: string
  readonly subjectId: string
  readonly reasonCode: string | null
  readonly outcome: string
  readonly source: string
  readonly sourceEventId: string | null
  readonly correlationId: string | null
  readonly payload: unknown
}

/**
 * Canonical bytes for one row.
 *
 * Order is fixed by this function and not by object key order, and every field is length-prefixed.
 * Length prefixes are not decoration: without them `actor='a'` + `action='bc'` and `actor='ab'` +
 * `action='c'` produce identical bytes, so two genuinely different rows would share a hash and one
 * could be substituted for the other. Concatenation without framing is the classic way a MAC over
 * structured data stops meaning anything.
 */
export function canonicalRow(row: HashableAuditRow): string {
  const parts: readonly string[] = [
    row.seq.toString(),
    row.id,
    row.occurredAt,
    row.recordedAt,
    row.actor,
    row.action,
    row.subjectKind,
    row.subjectId,
    row.reasonCode ?? '\u0000null',
    row.outcome,
    row.source,
    row.sourceEventId ?? '\u0000null',
    row.correlationId ?? '\u0000null',
    canonicalJson(row.payload),
  ]
  return parts.map((p) => `${Buffer.byteLength(p, 'utf8')}:${p}`).join('|')
}

/**
 * A stable JSON rendering. Keys are sorted at every depth.
 *
 * `JSON.stringify` preserves insertion order, so the same payload built two different ways would
 * hash differently — and a verifier that re-hashes a row read back from `jsonb` (which does not
 * preserve key order at all) would report a break on a row nobody touched. Sorting is what makes
 * the hash a function of the VALUE rather than of how it happened to be serialised.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'bigint') return `"${value.toString()}"`
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`
}

export function hashRow(prevHash: string, row: HashableAuditRow): string {
  return createHash('sha256')
    .update(`${Buffer.byteLength(prevHash, 'utf8')}:${prevHash}|${canonicalRow(row)}`)
    .digest('hex')
}

interface HeadRow {
  readonly seq: string | number
  readonly hash: string
}

/** The current head of the chain, or the genesis literal when the chain is empty. */
export async function chainHead(sql: Db | Tx): Promise<{ seq: bigint; hash: string }> {
  const rows = await sql<HeadRow[]>`select seq, hash from audit_events order by seq desc limit 1`
  const head = rows[0]
  if (!head) return { seq: 0n, hash: GENESIS_HASH }
  return { seq: BigInt(head.seq), hash: head.hash }
}

/**
 * Raised when a mirrored row has already been recorded. Not an error the caller should retry: the
 * event was delivered twice, which at-least-once delivery guarantees will happen.
 */
export class DuplicateMirrorError extends Error {
  readonly sourceEventId: string
  constructor(sourceEventId: string) {
    super(`audit event ${sourceEventId} has already been mirrored`)
    this.name = 'DuplicateMirrorError'
    this.sourceEventId = sourceEventId
  }
}

/**
 * Append one row, inside a transaction the caller already holds.
 *
 * **It must be the caller's transaction.** SD-15 requires the audit row and the change it
 * describes to commit together — "rolling back the change also rolls back the audit row, and
 * committing one commits both". An append on its own connection would give an audit log that
 * records actions which did not happen, which is the one failure mode worse than no audit log.
 */
export async function appendAudit(tx: Tx, input: AuditInput, now: () => Date = () => new Date()): Promise<AuditRow> {
  // Serialise appenders. Transaction-scoped, so a crash releases it.
  await tx`select pg_advisory_xact_lock(${CHAIN_LOCK_KEY.toString()}::bigint)`

  if (input.sourceEventId) {
    const existing = await tx<{ seq: string }[]>`
      select seq from audit_events where source_event_id = ${input.sourceEventId}
    `
    if (existing.length > 0) throw new DuplicateMirrorError(input.sourceEventId)
  }

  const head = await chainHead(tx)
  const seqRows = await tx<{ v: string }[]>`select nextval('audit_events_seq')::bigint as v`
  const seq = BigInt(seqRows[0]?.v ?? '0')
  const idRows = await tx<{ v: string }[]>`select gen_random_uuid()::text as v`
  const id = idRows[0]?.v ?? ''

  const at = now()
  const recordedAt = at.toISOString()
  const occurredAt = (input.occurredAt ?? at).toISOString()
  const payload = input.payload ?? {}

  const hashable: HashableAuditRow = {
    seq,
    id,
    occurredAt,
    recordedAt,
    actor: input.actor,
    action: input.action,
    subjectKind: input.subjectKind,
    subjectId: input.subjectId,
    reasonCode: input.reasonCode ?? null,
    outcome: input.outcome,
    source: input.source ?? 'admin-api',
    sourceEventId: input.sourceEventId ?? null,
    correlationId: input.correlationId ?? null,
    payload,
  }
  const hash = hashRow(head.hash, hashable)

  await tx`
    insert into audit_events (
      seq, id, occurred_at, recorded_at, actor, action, subject_kind, subject_id,
      reason_code, outcome, source, source_event_id, correlation_id, payload, prev_hash, hash
    ) values (
      ${seq.toString()}, ${id}, ${occurredAt}::timestamptz, ${recordedAt}::timestamptz,
      ${hashable.actor}, ${hashable.action}, ${hashable.subjectKind}, ${hashable.subjectId},
      ${hashable.reasonCode}, ${hashable.outcome}, ${hashable.source}, ${hashable.sourceEventId},
      ${hashable.correlationId}, ${tx.json(payload as Record<string, never>)},
      ${head.hash}, ${hash}
    )
  `

  return {
    ...hashable,
    outcome: hashable.outcome as AuditOutcome,
    payload,
    prevHash: head.hash,
    hash,
  }
}

/* ------------------------------------------------------------------------ verification */

export type BreakKind =
  | 'hash_mismatch'
  | 'link_mismatch'
  | 'checkpoint_missing'
  | 'checkpoint_mismatch'
  | 'checkpoint_truncated'

export interface ChainBreak {
  readonly kind: BreakKind
  readonly seq: bigint
  readonly detail: string
}

export interface VerifyResult {
  readonly ok: boolean
  readonly checked: number
  readonly from: bigint
  readonly to: bigint
  readonly headHash: string
  readonly totalEvents: number
  readonly breaks: readonly ChainBreak[]
}

interface StoredRow {
  readonly seq: string
  readonly id: string
  readonly occurred_at: Date
  readonly recorded_at: Date
  readonly actor: string
  readonly action: string
  readonly subject_kind: string
  readonly subject_id: string
  readonly reason_code: string | null
  readonly outcome: string
  readonly source: string
  readonly source_event_id: string | null
  readonly correlation_id: string | null
  readonly payload: Record<string, unknown>
  readonly prev_hash: string
  readonly hash: string
}

function toHashable(row: StoredRow): HashableAuditRow {
  return {
    seq: BigInt(row.seq),
    id: row.id,
    occurredAt: row.occurred_at.toISOString(),
    recordedAt: row.recorded_at.toISOString(),
    actor: row.actor,
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
}

export interface VerifyOptions {
  /**
   * Start from this sequence rather than from the last checkpoint. `0` re-verifies everything.
   *
   * The job passes nothing and resumes from the checkpoint, which is what keeps a nightly pass
   * over a year of audit cheap. An operator investigating a suspected tamper passes 0.
   */
  readonly from?: bigint
  /** Ceiling on rows examined in one pass. */
  readonly limit?: number
}

/**
 * Walk the chain and report every break.
 *
 * It returns ALL breaks rather than the first. A tamper that touched three rows produces three
 * findings, and an operator answering "what was changed" needs the set, not the earliest member
 * of it. The cost is bounded by `limit`.
 */
export async function verifyChain(sql: Db, options: VerifyOptions = {}): Promise<VerifyResult> {
  const limit = options.limit ?? 10_000
  const breaks: ChainBreak[] = []

  const checkpointRows = await sql<{ seq: string; hash: string; event_count: string }[]>`
    select seq, hash, event_count from audit_chain_checkpoints order by seq desc limit 1
  `
  const checkpoint = checkpointRows[0]

  const totalRows = await sql<{ n: string }[]>`select count(*)::bigint as n from audit_events`
  const totalEvents = Number(totalRows[0]?.n ?? '0')

  // ── The truncation check. A hash chain cannot see this on its own; see the file header.
  if (checkpoint) {
    const anchor = await sql<{ hash: string }[]>`
      select hash from audit_events where seq = ${checkpoint.seq}
    `
    const anchorHash = anchor[0]?.hash
    if (anchorHash === undefined) {
      breaks.push({
        kind: 'checkpoint_missing',
        seq: BigInt(checkpoint.seq),
        detail: `checkpoint names seq ${checkpoint.seq}, which is no longer in the log`,
      })
    } else if (anchorHash !== checkpoint.hash) {
      breaks.push({
        kind: 'checkpoint_mismatch',
        seq: BigInt(checkpoint.seq),
        detail: `checkpoint recorded hash ${checkpoint.hash} at seq ${checkpoint.seq}; the log now holds ${anchorHash}`,
      })
    }
    if (totalEvents < Number(checkpoint.event_count)) {
      breaks.push({
        kind: 'checkpoint_truncated',
        seq: BigInt(checkpoint.seq),
        detail: `checkpoint counted ${checkpoint.event_count} events; the log now holds ${totalEvents}`,
      })
    }
  }

  // Start one row BEFORE the resume point so the first link is checked rather than assumed. A
  // verifier that trusts its own starting row is a verifier that can be aimed past the tamper.
  const from = options.from ?? (checkpoint ? BigInt(checkpoint.seq) : 0n)
  const rows = await sql<StoredRow[]>`
    select seq, id, occurred_at, recorded_at, actor, action, subject_kind, subject_id,
           reason_code, outcome, source, source_event_id, correlation_id, payload, prev_hash, hash
      from audit_events
     where seq >= ${from.toString()}
     order by seq
     limit ${limit}
  `

  let expectedPrev: string | null = null
  let lastSeq = from
  let headHash = GENESIS_HASH

  for (const row of rows) {
    const seq = BigInt(row.seq)
    const recomputed = hashRow(row.prev_hash, toHashable(row))
    if (recomputed !== row.hash) {
      breaks.push({
        kind: 'hash_mismatch',
        seq,
        detail: `row ${seq} hashes to ${recomputed} but stores ${row.hash} — a hashed field was changed`,
      })
    }
    if (expectedPrev !== null && row.prev_hash !== expectedPrev) {
      breaks.push({
        kind: 'link_mismatch',
        seq,
        detail: `row ${seq} follows ${expectedPrev} in sequence but names ${row.prev_hash} as its predecessor`,
      })
    }
    if (expectedPrev === null && from === 0n && row.prev_hash !== GENESIS_HASH) {
      breaks.push({
        kind: 'link_mismatch',
        seq,
        detail: `the first row names ${row.prev_hash} rather than the genesis hash`,
      })
    }
    expectedPrev = row.hash
    headHash = row.hash
    lastSeq = seq
  }

  return {
    ok: breaks.length === 0,
    checked: rows.length,
    from,
    to: lastSeq,
    headHash,
    totalEvents,
    breaks,
  }
}

/**
 * Record a checkpoint at the current head.
 *
 * Only ever called after a clean verification. Checkpointing an unverified head would anchor the
 * tamper: the next pass would resume from a row the attacker wrote and declare it good.
 */
export async function writeCheckpoint(sql: Db, verifiedBy: string): Promise<{ seq: bigint; hash: string } | null> {
  const head = await chainHead(sql)
  if (head.seq === 0n) return null
  const count = await sql<{ n: string }[]>`select count(*)::bigint as n from audit_events`
  await sql`
    insert into audit_chain_checkpoints (seq, hash, event_count, verified_by)
    values (${head.seq.toString()}, ${head.hash}, ${count[0]?.n ?? '0'}, ${verifiedBy})
    on conflict (seq) do update
       set hash = excluded.hash, event_count = excluded.event_count,
           verified_at = now(), verified_by = excluded.verified_by
  `
  return head
}

/* ------------------------------------------------------------------------ reads */

export interface AuditQuery {
  readonly actor?: string
  readonly action?: string
  readonly subjectKind?: string
  readonly subjectId?: string
  readonly correlationId?: string
  readonly source?: string
  /** Seq to read backwards from, exclusive. The opaque cursor is the seq. */
  readonly before?: bigint
  readonly limit?: number
}

export interface AuditPage {
  readonly events: readonly AuditRow[]
  readonly nextCursor: string | null
}

/**
 * Read the log, newest first.
 *
 * Every filter is a column with an index behind it and none of them is free text: an operator
 * console that offers a LIKE over `payload` is a console that table-scans the estate's audit of
 * record during an incident. Correlation-id lookup is the workflow 13 §16 names — "one search box
 * accepts a cf.request_id … and fans out" — and it is an equality match on an indexed column.
 */
export async function readAudit(sql: Db, query: AuditQuery = {}): Promise<AuditPage> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), 200)
  const rows = await sql<StoredRow[]>`
    select seq, id, occurred_at, recorded_at, actor, action, subject_kind, subject_id,
           reason_code, outcome, source, source_event_id, correlation_id, payload, prev_hash, hash
      from audit_events
     where true
       ${query.actor ? sql`and actor = ${query.actor}` : sql``}
       ${query.action ? sql`and action = ${query.action}` : sql``}
       ${query.subjectKind ? sql`and subject_kind = ${query.subjectKind}` : sql``}
       ${query.subjectId ? sql`and subject_id = ${query.subjectId}` : sql``}
       ${query.correlationId ? sql`and correlation_id = ${query.correlationId}` : sql``}
       ${query.source ? sql`and source = ${query.source}` : sql``}
       ${query.before !== undefined ? sql`and seq < ${query.before.toString()}` : sql``}
     order by seq desc
     limit ${limit + 1}
  `

  const page = rows.slice(0, limit)
  const last = page[page.length - 1]

  // ══════════════════════════════════════════════════════════════════════════════════════════
  // RESTRICTION OF PROCESSING (Art. 18), APPLIED HERE BECAUSE IT CANNOT BE APPLIED TO THE ROW.
  //
  // The stored row is never edited — it is hash-chained, and `src/erasure.ts` carries the full
  // argument for why that makes in-place erasure unavailable and which lawful basis retains it.
  // What CAN be withdrawn is the disclosure, and this is the only place the log is disclosed.
  //
  // `payload` is the half that matters most. It is a mirrored copy of a producer's envelope and
  // is the only column in this table that can carry an actual name, handle or address, so it is
  // replaced wholesale rather than filtered — a key-by-key allowlist over somebody else's payload
  // shape is a rule that silently stops covering a field the day a producer adds one.
  //
  // Applied AFTER the page is selected, deliberately. Filtering erased subjects out of the query
  // would change `nextCursor` and the page size, so an operator paging through the log would see
  // pages of varying length and could infer exactly which rows were erased from the gaps — which
  // is the linkage this is meant to prevent.
  //
  // There is no unredacted route past this: no query parameter, no scope, no admin flag. Reading
  // the raw row means direct database access, which is a break-glass with its own controls, and
  // that is the right place for that decision to be made.
  // ══════════════════════════════════════════════════════════════════════════════════════════
  const userSubjects = page
    .filter((row) => row.subject_kind === ERASABLE_SUBJECT_KIND)
    .map((row) => row.subject_id)
  const erased = await erasedSubjects(sql, userSubjects)

  return {
    events: page.map((row) => {
      const restricted =
        row.subject_kind === ERASABLE_SUBJECT_KIND && erased.has(row.subject_id)
      return {
        seq: BigInt(row.seq),
        id: row.id,
        occurredAt: row.occurred_at.toISOString(),
        recordedAt: row.recorded_at.toISOString(),
        // `actor` is NOT restricted: it names the operator who acted, not the customer. An audit
        // whose actors are anonymous is not an audit. See `erasure.ts`'s per-table decision.
        actor: row.actor,
        action: row.action,
        subjectKind: row.subject_kind,
        subjectId: restricted ? RESTRICTED_SUBJECT : row.subject_id,
        reasonCode: row.reason_code,
        outcome: row.outcome as AuditOutcome,
        source: row.source,
        sourceEventId: row.source_event_id,
        correlationId: row.correlation_id,
        payload: restricted ? {} : row.payload,
        // The hashes are returned unchanged, and that is correct rather than an oversight: they
        // are the evidence the chain is intact, they are derived from data the reader is not
        // being shown, and a digest is not a re-identification path.
        prevHash: row.prev_hash,
        hash: row.hash,
      }
    }),
    nextCursor: rows.length > limit && last ? last.seq : null,
  }
}

/** The wire shape. `seq` is a string because a bigint is not a JSON number. */
export function auditToJson(row: AuditRow): Record<string, unknown> {
  return {
    seq: row.seq.toString(),
    id: row.id,
    occurredAt: row.occurredAt,
    recordedAt: row.recordedAt,
    actor: row.actor,
    action: row.action,
    subjectKind: row.subjectKind,
    subjectId: row.subjectId,
    reasonCode: row.reasonCode,
    outcome: row.outcome,
    source: row.source,
    sourceEventId: row.sourceEventId,
    correlationId: row.correlationId,
    payload: row.payload,
    prevHash: row.prevHash,
    hash: row.hash,
  }
}
