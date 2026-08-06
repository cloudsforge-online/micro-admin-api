/**
 * GDPR right-to-erasure, in the one service where erasure and integrity genuinely conflict.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **IS AN ADMIN AUDIT LOG ERASABLE AT ALL? NO — AND THE REASON IS NOT "IT WOULD BE HARD".**
 *
 * `audit_events` is a hash chain. `hashRow` covers `actor`, `action`, `subject_kind`, `subject_id`,
 * `reason_code`, `outcome`, `source`, `correlation_id` and the whole of `payload` (`audit.ts`'s
 * `canonicalRow`), and `audit_events_chain_uniq` makes each hash the predecessor of at most one
 * row. Rewriting `subject_id` on one row therefore invalidates that row's hash and every hash after
 * it. There is no partial version of this: the chain is either verifiable from genesis or it is
 * not, and a chain that has been legitimately rewritten once is indistinguishable, to the verifier
 * and to a regulator, from one that an operator rewrote to cover a theft.
 *
 * That is not an implementation detail to be worked around. **An audit trail exists precisely so
 * that it cannot be edited by the person it records**, and the subject of an admin action is very
 * often the person with the strongest motive to edit it. A "right to erasure" that let the subject
 * of an investigation rewrite the investigator's notes would be a right to destroy evidence.
 *
 * ── THE LAWFUL BASIS FOR RETENTION, NAMED ─────────────────────────────────────────────────────
 *
 *   **Art. 17(3)(b)** — processing necessary for compliance with a legal obligation. This is a
 *   crypto platform: records of administrative action on customer accounts, and of who took them,
 *   are the AML/CTF and financial record-keeping obligation, and the retention period is set by
 *   that obligation rather than by us.
 *
 *   **Art. 17(3)(e)** — establishment, exercise or defence of legal claims. The audit is the
 *   evidence in any dispute about what an operator did to an account: a freeze, a manual ledger
 *   adjustment, a reversal. Erasing it on request from the account holder would destroy the
 *   platform's only defence in a claim brought by that same account holder.
 *
 * ── AND THE PART THAT IS OFTEN OVERSTATED, STATED HONESTLY ────────────────────────────────────
 *
 * What actually remains here is thinner than "an audit log of a person" sounds. This service is a
 * BFF: there is no `users` table, no name, no email, no address, no balance — the header of
 * `migrations.ts` says so and the schema bears it out. `audit_events.subject_id` is a REFERENCE to
 * a row somebody else owns. Once `identity` has completed the deletion, that uuid resolves to
 * nobody anywhere in the estate, and what is left is a pseudonymous token beside a record of an
 * administrative action. That is a real and material reduction in what is retained, and it is why
 * retention here is proportionate rather than merely permitted.
 *
 * It is NOT a reason to do nothing, which is the failure mode this file exists to avoid. "Retained
 * under 17(3)" is a conclusion people reach and then stop at. Three things are still reachable, and
 * all three are implemented below.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT IS IMPLEMENTED, BEING THE REACHABLE HALF**
 *
 *   1. **A durable erasure register** (`audit_subject_erasures`). Art. 5(2) requires us to be able
 *      to DEMONSTRATE compliance, and 17(3) retention is only defensible if we can show which
 *      subjects asked, when, and under which event. It is also what makes 2 and 3 possible at all.
 *
 *   2. **Restriction of processing at every read surface** (Art. 18). The chain is untouched; the
 *      DISCLOSURE stops. `readAudit` replaces `subject_id` with the erasure marker and `payload`
 *      with `{}` for every row about an erased subject. `payload` is the half that matters most:
 *      it is a mirrored copy of a producer's envelope and is the only column here that can carry
 *      an actual name, handle or address. There is no unredacted route — not a query parameter,
 *      not a scope, not an admin flag. Reading the raw row means direct database access, which is
 *      a break-glass with its own controls, and that is the correct place for that decision.
 *
 *   3. **Pseudonymisation where it does NOT break integrity** — `approvals`. That table is not
 *      hash-chained, so the subject of a four-eyes approval CAN be de-linked with no loss of the
 *      property the table exists to enforce. It is done.
 *
 * ── PER-TABLE DECISION ────────────────────────────────────────────────────────────────────────
 *
 * | table                    | action   | reasoning, and lawful basis where retained            |
 * |--------------------------|----------|-------------------------------------------------------|
 * | audit_events             | RETAIN,  | Hash-chained. Editing any covered column invalidates  |
 * |  .subject_id             | restrict | this row's hash and every hash after it, destroying   |
 * |  .payload                |          | the tamper-evidence the service exists to provide.    |
 * |                          |          | Art. 17(3)(b) — AML/CTF record-keeping — and 17(3)(e) |
 * |                          |          | — defence of legal claims. Retained in the table,     |
 * |                          |          | withheld from every read surface (Art. 18).           |
 * | audit_events             | RETAIN   | `actor` names the OPERATOR who acted, not the         |
 * |  .actor                  |          | customer. An audit whose actors are anonymous is not  |
 * |                          |          | an audit. If the erased person IS an operator, the    |
 * |                          |          | same 17(3)(b)/(e) basis applies with more force: this |
 * |                          |          | is the record of what they did with their privileges. |
 * | audit_events             | RETAIN   | Only rows with `subject_kind = 'user'` are in scope   |
 * |  (other subject_kinds)   |          | AT ALL. `subject_id` is deliberately `text` and may   |
 * |                          |          | name a ledger entry, a market case, an account handle |
 * |                          |          | or an on-chain hash (`migrations.ts`). A uuid   |
 * |                          |          | collision between a user id and a ledger entry id     |
 * |                          |          | must not cause a ledger row to be restricted, so the  |
 * |                          |          | register carries the KIND and every read joins on     |
 * |                          |          | both columns. `audit_subject_erasures_user_only`      |
 * |                          |          | enforces it in the schema, not just here.             |
 * | audit_chain_checkpoints  | retain   | `(seq, hash, count)`. Names no subject at all, and is |
 * |                          |          | the only defence against truncation.                  |
 * | approvals.subject_id     | ANONYMISE| Not hash-chained. The four-eyes property is           |
 * |                          |          | `requested_by <> decided_by` and the execution        |
 * |                          |          | linkage — none of it needs to know WHICH customer the |
 * |                          |          | action was about. So the customer is de-linked, and   |
 * |                          |          | this is real erasure rather than restriction.         |
 * | approvals.requested_by   | RETAIN   | Both are OPERATORS. `approvals_no_self_approval` is   |
 * | approvals.decided_by     |          | the control SD-10 and 13 §16 require, and an approval |
 * |                          |          | whose two operators are anonymous cannot evidence     |
 * |                          |          | that two people were involved. Art. 17(3)(b)/(e).     |
 * | approvals.params,        | retain   | Operator-supplied parameters and the free-text        |
 * |  .reason, .decision_note |          | justification for a destructive action — the substance|
 * |                          |          | of the four-eyes record. Same basis. Not disclosed    |
 * |                          |          | with an erased subject beside them, because the       |
 * |                          |          | subject is gone from the row.                         |
 * | broadcasts, feature_flags| retain   | Operator-facing configuration. No subject column.     |
 * | engagement_*             | retain   | Policy caps and transfers between SERVICES, keyed on  |
 * |                          |          | a service name and an approval. No user column.       |
 * | idempotency_keys         | retain   | A route key and a response hash; names a urn, not a   |
 * |                          |          | person, and is the record that a charge was or was    |
 * |                          |          | not made.                                             |
 * | inbox                    | retain   | `(topic, event_id)`. The acknowledgement, and Art.    |
 * |                          |          | 5(2) accountability. Names an event, not a user.      |
 * | outbox                   | retain   | Nothing is emitted for an erasure — announcing it     |
 * |                          |          | would write a fresh row naming the person into every  |
 * |                          |          | subscriber's inbox.                                   |
 * | audit_subject_erasures   | RETAIN   | It holds the erased subject id, and that is           |
 * |                          |          | unavoidable: something has to say which rows to       |
 * |                          |          | restrict. Hashing it would buy nothing, because the   |
 * |                          |          | id it would hash is sitting in `audit_events` beside  |
 * |                          |          | it under the same retention. Art. 5(2), and 17(3)(b)  |
 * |                          |          | as part of the record it governs.                     |
 * ──────────────────────────────────────────────────────────────────────────────────────────────
 *
 * **THE MIRROR OF THE DELETION EVENT ITSELF IS KEPT, DELIBERATELY.** `identity.user.deleted` is
 * `audited: true` in `TOPIC_AUDIT` (`contracts/packages/events/src/audit.ts`), so the event
 * that requests the erasure appends its own audit row naming the subject. That row is the evidence
 * that the request was received and acted on, which is the thing Art. 5(2) asks for, and it is
 * restricted on read like every other row about that subject.
 */

import type { Sql, TransactionSql } from 'postgres'

export type Db = Sql
export type Tx = TransactionSql

/**
 * What a restricted `subject_id` reads as.
 *
 * A fixed marker rather than a per-subject token: a distinct token per person would let a reader
 * group an erased subject's rows back together, which is the linkage that restriction exists to
 * prevent. Every restricted row from every erased subject reads identically.
 */
export const RESTRICTED_SUBJECT = 'erased:restricted'

/** The one `subject_kind` an erasure may touch. See the header. */
export const ERASABLE_SUBJECT_KIND = 'user'

export interface ErasureOutcome {
  /** True when this event registered a new erasure; false when it was already registered. */
  readonly registered: boolean
  /** Approvals whose subject was de-linked. */
  readonly approvalsAnonymised: number
  /** Audit rows now restricted on read. Retained, never edited — see the header. */
  readonly auditRowsRestricted: number
}

/**
 * Record an erasure and act on everything reachable.
 *
 * Runs inside the caller's `withInbox` transaction, so the register entry, the approvals rewrite
 * and the inbox acknowledgement commit together or none of them does.
 *
 * Note what is NOT here: any statement that touches `audit_events`. That is the point, and the
 * `audit_events_immutable` trigger added alongside this makes it true of every other code path
 * too, rather than only of this one.
 */
export async function eraseSubject(
  tx: Tx,
  input: {
    readonly userId: string
    readonly sourceEventId: string
    readonly tombstoneAt: string | null
    readonly reason: string | null
  },
): Promise<ErasureOutcome> {
  const registered = await tx<{ subject_id: string }[]>`
    insert into audit_subject_erasures (subject_kind, subject_id, source_event_id, tombstone_at, reason)
    values (${ERASABLE_SUBJECT_KIND}, ${input.userId}, ${input.sourceEventId},
            ${input.tombstoneAt}, ${input.reason})
    on conflict (subject_kind, subject_id) do nothing
    returning subject_id
  `

  // `subject_kind` is in the predicate, not just `subject_id`. `subject_id` is `text` and may name
  // a ledger entry or a market case, so matching on the id alone would restrict — or worse,
  // rewrite — a row about something that is not a person and cannot be erased.
  const approvals = await tx<{ id: string }[]>`
    update approvals set subject_id = ${RESTRICTED_SUBJECT}
     where subject_kind = ${ERASABLE_SUBJECT_KIND} and subject_id = ${input.userId}
    returning id
  `

  // Counted, not touched. This is the number of rows that will read as restricted from now on,
  // and it is worth returning because "we retained N rows under 17(3)" is the answer an operator
  // or a regulator actually asks for.
  const [restricted] = await tx<{ n: string }[]>`
    select count(*) as n from audit_events
     where subject_kind = ${ERASABLE_SUBJECT_KIND} and subject_id = ${input.userId}
  `

  return {
    registered: registered.length > 0,
    approvalsAnonymised: approvals.length,
    auditRowsRestricted: Number(restricted?.n ?? 0),
  }
}

/**
 * The set of erased user subjects, for the read path.
 *
 * One query per page rather than a join per row: the register is small — it holds one row per
 * erasure request, not per audit row — and a `where subject_id = any(...)` against a page of at
 * most 200 rows is cheaper and far easier to read than correlating a subquery into `readAudit`'s
 * already-conditional SQL.
 */
export async function erasedSubjects(sql: Db | Tx, subjectIds: readonly string[]): Promise<Set<string>> {
  if (subjectIds.length === 0) return new Set()
  const rows = await sql<{ subject_id: string }[]>`
    select subject_id from audit_subject_erasures
     where subject_kind = ${ERASABLE_SUBJECT_KIND} and subject_id = any(${subjectIds as string[]})
  `
  return new Set(rows.map((row) => row.subject_id))
}
