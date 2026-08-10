/**
 * The approval queue. Two operators, or nothing happens.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE REQUESTER MAY NOT BE THE APPROVER, AND THAT IS ENFORCED IN THREE PLACES.**
 *
 *   1. `decide()` refuses it with `SelfApprovalError`, so an operator gets a sentence explaining
 *      what happened rather than a database error code.
 *   2. `approvals_no_self_approval` (migrations.ts) refuses it as a CHECK constraint, so no code
 *      path — including one written next year by somebody who has not read this file — can get
 *      past it.
 *   3. The UPDATE in `decide()` carries `and requested_by <> ${operator}` in its WHERE clause, so
 *      even a transaction that somehow reached the write claims no row.
 *
 * Three is not paranoia about one rule; it is the recognition that 13-operational-model.md
 * says self-approval "is refused by the service, not by documentation" about the one control that
 * stands between a single compromised operator credential and a manual ledger adjustment.
 * `approvals.test.ts` proves all three independently, including by going straight at the database
 * with the route bypassed.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **AND THE APPROVER MAY NOT BE THE SUBJECT — micro-org#317, ADDED SECOND AND FOR A REASON.**
 *
 * Everything above counts SIGNATURES. It proves two different operators touched the row and says
 * nothing about who the row is FOR. That was enough while every action in the catalogue named a
 * ledger entry, a moderation case or an entitlement — none of which is a person — and stopped
 * being enough the moment `identity.role.grant` landed, which was the day the catalogue gained an
 * action whose subject IS an operator.
 *
 * The hole: A raises `identity.role.grant` naming B, and B approves it. `requested_by <>
 * decided_by` holds, all three layers above pass, the audit row names two operators, and B has
 * just granted themselves `admin`. Nobody acted alone and the control still failed, because "two
 * operators" was chosen so that the person who BENEFITS is not the person who DECIDES. The
 * requester/decider split is how that property is usually spelled; it is not what it means.
 *
 * So the beneficiary is checked in the same three places, deliberately mirroring the shape above
 * rather than inventing a second one:
 *
 *   1. `decide()` refuses it with `SubjectApprovalError` — its own class, its own sentence, its own
 *      counter, because "you cannot decide your own request" would be a lie here.
 *   2. `approvals_decider_is_not_the_subject` (migrations.ts version 12) refuses it as a CHECK, so
 *      a future code path that has not read this file cannot get past it.
 *   3. The UPDATE carries the same predicate in its WHERE clause, so a concurrent decision cannot
 *      slip between the read and the write.
 *
 * **THE REQUESTER IS NOT COVERED, AND THAT IS THE DECISION RATHER THAN THE OVERSIGHT.** Raising a
 * request that names yourself is ASKING. Somebody else still signs it, and forbidding it would only
 * mean asking a colleague to type the request for you — which hides who wanted the role while
 * changing nothing about who authorised it, and makes the audit row less true.
 *
 * **WHAT THIS STILL DOES NOT DO.** It is any two admins. There is no role split, no N-of-M, and no
 * rule that a more sensitive action needs a differently-qualified second signature. #317 names that
 * separately and it is a bigger change than a predicate — it needs a notion of operator ROLES that
 * this service does not have and, per #316, should not grow ahead of the #165 capability inventory.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **AN APPROVAL IS CONSENT TO AN ACTION IN A CONTEXT, AND THE CONTEXT DOES NOT KEEP.** A pending
 * request expires. Without expiry, a request raised during one incident is approved during the
 * next, by somebody who was not in the room for either — and the audit row would say two
 * operators agreed, which would be true and misleading at the same time.
 *
 * **AN EXPIRED REQUEST IS NOT A REJECTED ONE.** It carries no `decided_by`, because nobody
 * decided anything, and `approvals_execution_needs_approval` therefore makes it unexecutable by
 * construction rather than by a state check somebody could reorder.
 *
 * **EXECUTION IS RECORDED ON THE APPROVED ROW.** Not in a second table. "Was this authorised" and
 * "did it run" are then one row and cannot be answered by two rows that disagree — which is the
 * shape of every reconciliation problem in this estate.
 */

import type { Sql, TransactionSql } from 'postgres'
import { appendAudit, type AuditRow } from './audit.ts'

export type Db = Sql
export type Tx = TransactionSql

export type ApprovalState = 'pending' | 'approved' | 'rejected' | 'expired'
export type ExecutionOutcome = 'succeeded' | 'failed'

/**
 * The reason codes a request may carry. A closed list, per 13 §16: "destructive ones require a
 * reason code from a closed list".
 *
 * Free text is also required and also stored — the code is what a dashboard groups by, the text is
 * what a human reads six months later. Neither substitutes for the other: a free-text-only field
 * cannot be counted, and a code-only field cannot be understood.
 */
export const REASON_CODES: readonly string[] = Object.freeze([
  'incident_remediation',
  'customer_dispute',
  'fraud_response',
  'regulatory_request',
  'data_correction',
  'scheduled_maintenance',
  'security_response',
])

export class ApprovalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ApprovalError'
  }
}

/** The four-eyes refusal. Its own class so the route can answer 403 with a specific sentence. */
export class SelfApprovalError extends ApprovalError {
  constructor() {
    super('an approval request cannot be decided by the operator who raised it')
    this.name = 'SelfApprovalError'
  }
}

/**
 * The four-eyes refusal that counts the BENEFICIARY rather than the signatures — micro-org#317.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **ITS OWN CLASS, NOT A SECOND MESSAGE ON `SelfApprovalError`.** The two refusals answer the same
 * HTTP status and mean different things, and an operator who reads "you cannot approve your own
 * request" when they have in fact approved somebody else's will conclude the service is broken and
 * find another way. The sentence has to name what actually happened, and a metric that counts the
 * two together would hide the more interesting one: an operator deciding on a request that names
 * them is worth a look even when it is innocent, which self-approval attempts mostly are not.
 * `server.ts` maps this to its own error code and its own counter.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export class SubjectApprovalError extends ApprovalError {
  constructor() {
    super('an approval request that names an operator as its subject cannot be decided by that operator')
    this.name = 'SubjectApprovalError'
  }
}

/** The request is not in a state that admits this transition. */
export class ApprovalStateError extends ApprovalError {
  constructor(message: string) {
    super(message)
    this.name = 'ApprovalStateError'
  }
}

export class ApprovalNotFoundError extends ApprovalError {
  constructor(id: string) {
    super(`no approval request ${id}`)
    this.name = 'ApprovalNotFoundError'
  }
}

export interface Approval {
  readonly id: string
  readonly action: string
  readonly subjectKind: string
  readonly subjectId: string
  readonly params: Record<string, unknown>
  readonly reasonCode: string
  readonly reason: string
  readonly requestedBy: string
  readonly requestedAt: string
  readonly expiresAt: string
  readonly state: ApprovalState
  readonly decidedBy: string | null
  readonly decidedAt: string | null
  readonly decisionNote: string | null
  readonly executedAt: string | null
  readonly executionOutcome: ExecutionOutcome | null
  readonly executionDetail: Record<string, unknown> | null
  readonly correlationId: string | null
}

interface ApprovalRow {
  readonly id: string
  readonly action: string
  readonly subject_kind: string
  readonly subject_id: string
  readonly params: Record<string, unknown>
  readonly reason_code: string
  readonly reason: string
  readonly requested_by: string
  readonly requested_at: Date
  readonly expires_at: Date
  readonly state: ApprovalState
  readonly decided_by: string | null
  readonly decided_at: Date | null
  readonly decision_note: string | null
  readonly executed_at: Date | null
  readonly execution_outcome: ExecutionOutcome | null
  readonly execution_detail: Record<string, unknown> | null
  readonly correlation_id: string | null
}

const COLUMNS = `id, action, subject_kind, subject_id, params, reason_code, reason,
                 requested_by, requested_at, expires_at, state, decided_by, decided_at,
                 decision_note, executed_at, execution_outcome, execution_detail, correlation_id`

function toApproval(row: ApprovalRow): Approval {
  return {
    id: row.id,
    action: row.action,
    subjectKind: row.subject_kind,
    subjectId: row.subject_id,
    params: row.params,
    reasonCode: row.reason_code,
    reason: row.reason,
    requestedBy: row.requested_by,
    requestedAt: row.requested_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
    state: row.state,
    decidedBy: row.decided_by,
    decidedAt: row.decided_at?.toISOString() ?? null,
    decisionNote: row.decision_note,
    executedAt: row.executed_at?.toISOString() ?? null,
    executionOutcome: row.execution_outcome,
    executionDetail: row.execution_detail,
    correlationId: row.correlation_id,
  }
}

/**
 * The estate principal an approval's subject names, or `null` when it names no person at all.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TWO COLUMNS ARE IN DIFFERENT VOCABULARIES ON PURPOSE, AND THIS IS THE CONVERSION.**
 *
 * `subject_id` is whatever identifier the UPSTREAM uses — a ledger entry id, a moderation case id,
 * a bare uuid for identity's `PUT /internal/users/:id/roles`. `decided_by` is an estate PRINCIPAL,
 * pinned to `^user:…` by `approvals_decider_is_a_principal`. Comparing them directly would be
 * comparing a uuid to `user:<uuid>` and would silently never match — which is the failure mode
 * where a security check exists, passes every test somebody thought to write, and enforces nothing.
 *
 * Exported so the check can be read by the tests that prove it, and written as a function rather
 * than a template literal at the call site so that the day a second subject kind names a person
 * there is exactly one place that has to learn about it. `subject_kind` is the discriminator
 * because it is the column the catalogue sets from `ActionSpec.subjectKind`, so a new action
 * naming a person cannot arrive without passing through it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function principalForSubject(subjectKind: string, subjectId: string): string | null {
  return subjectKind === 'user' ? `user:${subjectId}` : null
}

export interface RequestInput {
  readonly action: string
  readonly subjectKind: string
  readonly subjectId: string
  readonly params: Record<string, unknown>
  readonly reasonCode: string
  readonly reason: string
  /** `user:<uuid>`. Derived from the verified token, never from the body. */
  readonly requestedBy: string
  readonly ttlMinutes: number
  readonly correlationId?: string | null
}

/**
 * Raise a request, and audit the raising of it.
 *
 * The audit row and the approval row commit together — SD-15. That matters more here than
 * elsewhere: an approval request that exists with no audit row is a request nobody can attribute,
 * and an audit row for a request that rolled back is a record of something that did not happen.
 */
export async function requestApproval(
  tx: Tx,
  input: RequestInput,
  now: () => Date = () => new Date(),
): Promise<{ approval: Approval; audit: AuditRow }> {
  if (!REASON_CODES.includes(input.reasonCode)) {
    throw new ApprovalError(
      `reasonCode must be one of ${REASON_CODES.join(', ')} (got ${input.reasonCode})`,
    )
  }
  const expiresAt = new Date(now().getTime() + input.ttlMinutes * 60_000)

  const rows = await tx<ApprovalRow[]>`
    insert into approvals (
      action, subject_kind, subject_id, params, reason_code, reason,
      requested_by, expires_at, correlation_id
    ) values (
      ${input.action}, ${input.subjectKind}, ${input.subjectId},
      ${tx.json(input.params as Record<string, never>)},
      ${input.reasonCode}, ${input.reason}, ${input.requestedBy},
      ${expiresAt.toISOString()}::timestamptz, ${input.correlationId ?? null}
    )
    returning ${tx.unsafe(COLUMNS)}
  `
  const approval = toApproval(rows[0]!)

  const audit = await appendAudit(
    tx,
    {
      actor: input.requestedBy,
      action: 'admin.approval.requested',
      subjectKind: 'approval',
      subjectId: approval.id,
      outcome: 'allowed',
      reasonCode: input.reasonCode,
      correlationId: input.correlationId ?? null,
      payload: {
        requestedAction: input.action,
        target: { kind: input.subjectKind, id: input.subjectId },
        params: input.params,
        reason: input.reason,
        expiresAt: approval.expiresAt,
      },
    },
    now,
  )

  return { approval, audit }
}

export interface DecisionInput {
  readonly id: string
  /** `user:<uuid>`. Derived from the verified token, never from the body. */
  readonly operator: string
  readonly grant: boolean
  readonly note?: string | null
  readonly correlationId?: string | null
}

/**
 * Approve or reject a pending request.
 *
 * The self-approval refusal is checked **before** the UPDATE so the operator gets a specific 403,
 * and again **inside** the UPDATE's WHERE clause so a race between two decisions cannot land one
 * that the pre-check would have refused. The CHECK constraint is the third.
 */
export async function decide(
  tx: Tx,
  input: DecisionInput,
  now: () => Date = () => new Date(),
): Promise<{ approval: Approval; audit: AuditRow }> {
  const current = await tx<ApprovalRow[]>`
    select ${tx.unsafe(COLUMNS)} from approvals where id = ${input.id} for update
  `
  const row = current[0]
  if (!row) throw new ApprovalNotFoundError(input.id)
  if (row.state !== 'pending') {
    throw new ApprovalStateError(`approval ${input.id} is already ${row.state}`)
  }
  // ── FOUR EYES, first of three. See the file header.
  if (row.requested_by === input.operator) throw new SelfApprovalError()
  // ── THE BENEFICIARY, first of three. Same three-layer shape, a different question. See the
  //    file header, and `principalForSubject` for why the conversion is a function.
  if (principalForSubject(row.subject_kind, row.subject_id) === input.operator) {
    throw new SubjectApprovalError()
  }
  if (row.expires_at.getTime() <= now().getTime()) {
    throw new ApprovalStateError(`approval ${input.id} expired at ${row.expires_at.toISOString()}`)
  }

  const nextState: ApprovalState = input.grant ? 'approved' : 'rejected'
  const updated = await tx<ApprovalRow[]>`
    update approvals
       set state = ${nextState},
           decided_by = ${input.operator},
           decided_at = ${now().toISOString()}::timestamptz,
           decision_note = ${input.note ?? null}
     where id = ${input.id}
       and state = 'pending'
       -- ── FOUR EYES, second of three. A concurrent decision cannot slip past the read above.
       and requested_by <> ${input.operator}
       -- ── THE BENEFICIARY, second of three. Written in SQL rather than reusing the value the
       --    pre-check computed, so it binds the row AS IT IS AT WRITE TIME. The subject columns
       --    are immutable today and this costs nothing; the day something makes them mutable,
       --    this is the layer that does not have to be remembered.
       and (subject_kind <> 'user' or 'user:' || subject_id <> ${input.operator})
    returning ${tx.unsafe(COLUMNS)}
  `
  const after = updated[0]
  if (!after) throw new ApprovalStateError(`approval ${input.id} was decided concurrently`)
  const approval = toApproval(after)

  const audit = await appendAudit(
    tx,
    {
      actor: input.operator,
      action: input.grant ? 'admin.approval.granted' : 'admin.approval.rejected',
      subjectKind: 'approval',
      subjectId: approval.id,
      outcome: 'allowed',
      reasonCode: approval.reasonCode,
      correlationId: input.correlationId ?? approval.correlationId,
      payload: {
        requestedAction: approval.action,
        target: { kind: approval.subjectKind, id: approval.subjectId },
        // Both operators are named on the decision row, so the pair is one lookup rather than a
        // join back to the request. An audit trail that needs a join to answer "who were the two
        // people" is an audit trail nobody uses under pressure.
        requestedBy: approval.requestedBy,
        approvedBy: input.operator,
        note: input.note ?? null,
      },
    },
    now,
  )

  return { approval, audit }
}

export interface ExecutionRecord {
  readonly id: string
  readonly outcome: ExecutionOutcome
  readonly detail: Record<string, unknown>
  /** The operator whose approval authorised the run — never the service. */
  readonly actor: string
  readonly correlationId?: string | null
}

/**
 * Record that an approved action ran.
 *
 * `where state = 'approved' and executed_at is null` is what makes this at-most-once: a retry of
 * the approve route, or a second worker, claims no row. `approvals_execution_needs_approval` is
 * the constraint behind it.
 */
export async function recordExecution(
  tx: Tx,
  record: ExecutionRecord,
  now: () => Date = () => new Date(),
): Promise<{ approval: Approval; audit: AuditRow } | null> {
  const rows = await tx<ApprovalRow[]>`
    update approvals
       set executed_at = ${now().toISOString()}::timestamptz,
           execution_outcome = ${record.outcome},
           execution_detail = ${tx.json(record.detail as Record<string, never>)}
     where id = ${record.id}
       and state = 'approved'
       and executed_at is null
    returning ${tx.unsafe(COLUMNS)}
  `
  const row = rows[0]
  if (!row) return null
  const approval = toApproval(row)

  const audit = await appendAudit(
    tx,
    {
      actor: record.actor,
      action: 'admin.approval.executed',
      subjectKind: approval.subjectKind,
      subjectId: approval.subjectId,
      outcome: record.outcome === 'succeeded' ? 'allowed' : 'failed',
      reasonCode: approval.reasonCode,
      correlationId: record.correlationId ?? approval.correlationId,
      payload: {
        approvalId: approval.id,
        requestedAction: approval.action,
        requestedBy: approval.requestedBy,
        approvedBy: approval.decidedBy,
        detail: record.detail,
      },
    },
    now,
  )

  return { approval, audit }
}

export interface ApprovalQuery {
  readonly state?: ApprovalState
  readonly action?: string
  readonly requestedBy?: string
  readonly limit?: number
}

export async function listApprovals(sql: Db, query: ApprovalQuery = {}): Promise<readonly Approval[]> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), 200)
  const rows = await sql<ApprovalRow[]>`
    select ${sql.unsafe(COLUMNS)} from approvals
     where true
       ${query.state ? sql`and state = ${query.state}` : sql``}
       ${query.action ? sql`and action = ${query.action}` : sql``}
       ${query.requestedBy ? sql`and requested_by = ${query.requestedBy}` : sql``}
     order by requested_at desc
     limit ${limit}
  `
  return rows.map(toApproval)
}

export async function findApproval(sql: Db | Tx, id: string): Promise<Approval | null> {
  const rows = await sql<ApprovalRow[]>`select ${sql.unsafe(COLUMNS)} from approvals where id = ${id}`
  const row = rows[0]
  return row ? toApproval(row) : null
}

/**
 * Expire pending requests past their deadline. Returns the ids expired.
 *
 * A leased job calls this — never a `setInterval`, rule 8. Expiry is a domain change with an audit
 * consequence, so two replicas running it on a timer would write two audit rows for one expiry and
 * the log would show an action taken twice.
 */
export async function expirePending(
  tx: Tx,
  /**
   * The principal, not the process. `service:admin-api` — never `service:admin-api@<replica>`.
   *
   * `audit_events_actor_is_a_principal` refuses the second form, and it is right to: an actor is
   * an IDENTITY, and a replica name is not one. Two replicas are the same principal doing the same
   * thing, and an audit that treated them as different actors would make "how many distinct
   * parties touched this" unanswerable by counting. The replica lands in the payload, where it is
   * forensic detail rather than attribution.
   */
  actor: string,
  instanceId: string,
  limit = 200,
  now: () => Date = () => new Date(),
): Promise<readonly string[]> {
  const rows = await tx<{ id: string; action: string; reason_code: string; correlation_id: string | null }[]>`
    update approvals
       set state = 'expired'
     where id in (
       select id from approvals
        where state = 'pending' and expires_at <= ${now().toISOString()}::timestamptz
        order by expires_at
        limit ${limit}
        for update skip locked
     )
    returning id, action, reason_code, correlation_id
  `
  for (const row of rows) {
    await appendAudit(
      tx,
      {
        actor,
        action: 'admin.approval.expired',
        subjectKind: 'approval',
        subjectId: row.id,
        outcome: 'refused',
        reasonCode: row.reason_code,
        correlationId: row.correlation_id,
        payload: {
          requestedAction: row.action,
          reason: 'no second operator answered before the deadline',
          instanceId,
        },
      },
      now,
    )
  }
  return rows.map((r) => r.id)
}

export function approvalToJson(approval: Approval): Record<string, unknown> {
  return { ...approval }
}
