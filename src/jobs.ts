/**
 * The background work, all of it leased.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job, and `setInterval` doing
 * domain work fails review. There is no `setInterval` in this repository and CI greps for one.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE LEASE KEY NAMES THE CONTENDED RESOURCE, NOT THE ROW.** Getting this wrong is the mistake
 * `@cloudsforge/jobs` is written to make hard, and here the resources are:
 *
 *   `audit.verify`      key `audit:chain`  — there is ONE chain. Two verifiers would both walk it
 *                                            and both write a checkpoint, and the second's
 *                                            checkpoint could anchor a head the first had not
 *                                            finished checking.
 *   `outbox.relay`      key `outbox`       — there is ONE unpublished stream. Two relays deliver
 *                                            every event twice.
 *   `approvals.expire`  key `approvals`    — expiry writes an audit row per request. Two expirers
 *                                            would show one expiry twice in the audit of record.
 *   `idempotency.reap`  key `idempotency`  — one table, one DELETE loop.
 *
 * None of these keys is a row id, because none of the contended resources is a row.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **THE VERIFICATION JOB DOES NOT WRITE A CHECKPOINT WHEN THE CHAIN IS BROKEN.** Checkpointing an
 * unverified head would anchor the tamper: the next pass resumes from a row the attacker wrote and
 * declares everything before it good. SD-16 makes a break a P0, and a P0 whose detection is
 * silently disabled by its own detector is worse than no detector.
 */

import { JobQueue, JobRunner, backoffFor, type Handler } from '@cloudsforge/jobs'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { verifyChain, writeCheckpoint } from './audit.ts'
import { expirePending } from './approvals.ts'
import { reapIdempotencyKeys } from './idempotency.ts'
import { createRelay, type Db } from './outbox.ts'

/**
 * This service's own principal, for the audit rows its background work writes.
 *
 * The replica is NOT part of it: `audit_events_actor_is_a_principal` refuses `service:x@replica`,
 * and correctly — an actor is an identity, and two replicas are the same identity. The replica
 * name goes in the payload. (`audit_chain_checkpoints.verified_by` is not an actor and does carry
 * it, because "which replica last verified" is exactly what an operator chasing a stalled
 * verification wants.)
 */
export const SERVICE_PRINCIPAL = 'service:admin-api'

export const AUDIT_VERIFY = 'audit.verify'
export const OUTBOX_RELAY = 'outbox.relay'
export const APPROVALS_EXPIRE = 'approvals.expire'
export const IDEMPOTENCY_REAP = 'idempotency.reap'

/** Every recurring job, its lease key, and how long until it runs again. */
export const RECURRING: ReadonlyArray<{ kind: string; key: string; everyMs: number }> = Object.freeze([
  { kind: OUTBOX_RELAY, key: 'outbox', everyMs: 2_000 },
  { kind: APPROVALS_EXPIRE, key: 'approvals', everyMs: 60_000 },
  // Nightly, per SD-16's "hash-chain continuity … nightly". The interval is what makes the
  // window in which a tamper goes unnoticed at most one day.
  { kind: AUDIT_VERIFY, key: 'audit:chain', everyMs: 24 * 60 * 60_000 },
  { kind: IDEMPOTENCY_REAP, key: 'idempotency', everyMs: 6 * 60 * 60_000 },
])

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly metrics: Metrics
  readonly signingSecret: string
  readonly instanceId: string
  readonly auditVerifyBatch: number
  readonly idempotencyTtlDays: number
  readonly now?: () => Date
}

/**
 * The audit chain verifier. Exported so a route and a test can run it without the runner.
 *
 * It resumes from the last checkpoint rather than re-walking a year of audit every night, which is
 * what makes a nightly full-estate check affordable. `verifyChain` starts one row BEFORE the
 * resume point so the first link is checked rather than assumed — a verifier that trusts its own
 * starting row is a verifier that can be aimed past the tamper.
 */
export function createAuditVerifier(deps: JobDeps): Handler {
  return async () => {
    const result = await verifyChain(deps.sql, { limit: deps.auditVerifyBatch })
    deps.metrics.set('admin_audit_chain_length', result.totalEvents)
    deps.metrics.set('admin_audit_chain_breaks', result.breaks.length)

    if (!result.ok) {
      // ── P0 (SD-16). Every break is logged, not just the first: an operator answering "what was
      // changed" needs the set. And NO checkpoint is written — see the file header.
      deps.metrics.set('admin_audit_chain_verified_seq', 0)
      deps.logger.fatal('AUDIT CHAIN BROKEN', {
        checked: result.checked,
        from: result.from.toString(),
        to: result.to.toString(),
        breaks: result.breaks.map((b) => ({ kind: b.kind, seq: b.seq.toString(), detail: b.detail })),
      })
      // Thrown so the job fails, retries with backoff, and shows in `jobs_failed_total`. A broken
      // chain that logged and returned success would be a P0 that never pages.
      throw new Error(`audit chain verification found ${result.breaks.length} break(s)`)
    }

    const checkpoint = await writeCheckpoint(deps.sql, `${SERVICE_PRINCIPAL}@${deps.instanceId}`)
    deps.metrics.set('admin_audit_chain_verified_seq', Number(checkpoint?.seq ?? 0n))
    deps.logger.info('audit chain verified', {
      checked: result.checked,
      throughSeq: result.to.toString(),
      totalEvents: result.totalEvents,
    })
  }
}

export function createApprovalExpirer(deps: JobDeps): Handler {
  const now = deps.now ?? (() => new Date())
  return async () => {
    const expired = await deps.sql.begin(async (tx) => ({
      value: await expirePending(tx, SERVICE_PRINCIPAL, deps.instanceId, 200, now),
    }))
    if (expired.value.length > 0) {
      deps.metrics.increment('admin_approvals_expired_total', {}, expired.value.length)
      deps.logger.info('approval requests expired', { count: expired.value.length })
    }
  }
}

export function createIdempotencyReaper(deps: JobDeps): Handler {
  return async () => {
    const removed = await reapIdempotencyKeys(deps.sql, deps.idempotencyTtlDays)
    if (removed > 0) deps.logger.info('idempotency keys reaped', { removed })
  }
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  return runner
    .register(AUDIT_VERIFY, createAuditVerifier(deps))
    .register(OUTBOX_RELAY, createRelay({ sql: deps.sql, logger: deps.logger, signingSecret: deps.signingSecret }))
    .register(APPROVALS_EXPIRE, createApprovalExpirer(deps))
    .register(IDEMPOTENCY_REAP, createIdempotencyReaper(deps))
}

/**
 * Put every recurring job in the queue once.
 *
 * `onConflict: 'keep'` is the point: N replicas booting together seed the same four rows and end
 * up with four, not 4N. The unique `(kind, key)` in the jobs table is what makes that true.
 */
export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep' })
  }
}

/**
 * Put a recurring job back after it runs.
 *
 * A recurring job is enqueued once and re-enqueued on completion rather than being scheduled by a
 * timer, so the schedule survives a restart and cannot be run twice by two replicas.
 *
 * **A FAILED recurring job is rescheduled too, and that is not the same as retrying it.**
 * `JobQueue.fail` already reschedules the row with backoff, so re-enqueueing after a failure would
 * be a second schedule for the same key — which `(kind, key)` collapses, but only by luck of the
 * `keep` mode. So this reschedules only on `completed`, and lets the queue's own backoff own the
 * failure path. The audit verifier depends on that: a broken chain throws, the queue retries with
 * backoff, and the retries stop being free once the row dead-letters — which is what leaves a
 * durable record that verification could not pass.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: { type: string; kind?: string; key?: string }) => void {
  const byKind = new Map(RECURRING.map((job) => [job.kind, job]))
  return (event) => {
    if (event.type !== 'completed' || !event.kind) return
    const spec = byKind.get(event.kind)
    if (!spec) return
    void queue
      .enqueue({
        kind: spec.kind,
        key: spec.key,
        runAt: new Date(Date.now() + spec.everyMs),
        onConflict: 'earliest',
      })
      .catch((err: unknown) => logger.error('could not reschedule a recurring job', { kind: spec.kind, err }))
  }
}

/** Re-exported so `index.ts` and the tests use one backoff. */
export { backoffFor }
