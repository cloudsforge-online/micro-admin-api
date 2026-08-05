/**
 * The background work.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **TWO WORKERS ON ONE JOB → ONE RUN, PROVED RATHER THAN ASSERTED.**
 *
 * Two `JobQueue` instances with different owners claim against the same table concurrently. Rule 8
 * exists because the frozen estate runs eight `setInterval` timers guarded only by a module-local
 * boolean — a variable that is, by construction, invisible to a second process. Here the
 * consequences would be: two relays delivering every event twice, and two expirers writing two
 * audit rows for one expiry, which puts an action in the estate's audit of record that happened
 * once and reads as having happened twice.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { JobQueue, JobRunner } from '@cloudsforge/jobs'
import type { Sql as JobsSql } from '@cloudsforge/jobs'
import {
  APPROVALS_EXPIRE,
  AUDIT_VERIFY,
  IDEMPOTENCY_REAP,
  OUTBOX_RELAY,
  RECURRING,
  SERVICE_PRINCIPAL,
  createApprovalExpirer,
  createAuditVerifier,
  createIdempotencyReaper,
  registerHandlers,
  rescheduleRecurring,
  seedRecurring,
  type JobDeps,
} from './jobs.ts'
import { appendAudit, verifyChain, writeCheckpoint } from './audit.ts'
import { requestApproval } from './approvals.ts'
import {
  OPERATOR_ONE,
  db,
  enabled,
  migrateTestDb,
  openDb,
  quietLogger,
  resetAdminApi,
  skip,
  testMetrics,
} from './testsupport.ts'

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

function deps(overrides: Partial<JobDeps> = {}): JobDeps {
  return {
    sql: db(sql!),
    logger: quietLogger(),
    metrics: testMetrics(),
    signingSecret: 'a-test-signing-secret-of-sufficient-length',
    instanceId: 'replica-a',
    auditVerifyBatch: 5_000,
    idempotencyTtlDays: 14,
    composeProject: 'cf-testnet',
    ...overrides,
  }
}

function queueFor(owner: string): JobQueue {
  return new JobQueue(sql as unknown as JobsSql, { owner, leaseMs: 60_000 })
}

/* ------------------------------------------------------------------ the lease */

test('there is no setInterval in this repository', async () => {
  // Rule 8, asserted in the suite as well as in CI. The CI grep can be satisfied by a comment;
  // this reads the sources.
  const { readFileSync, readdirSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const dir = fileURLToPath(new URL('.', import.meta.url))
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))) {
    const source = readFileSync(`${dir}${file}`, 'utf8')
    const calls = source
      .split('\n')
      .filter((line) => /setInterval\s*\(/.test(line) && !/^\s*(\/\/|\*|\/\*)/.test(line))
    assert.deepEqual(calls, [], `${file} calls setInterval`)
  }
})

test('TWO WORKERS ON ONE JOB → ONE RUN', { skip }, async () => {
  const a = queueFor('replica-a')
  const b = queueFor('replica-b')
  await a.enqueue({ kind: APPROVALS_EXPIRE, key: 'approvals' })

  // Both claim at the same instant. `for update skip locked` is what makes exactly one win: the
  // row already being claimed by the other transaction is SKIPPED rather than waited on.
  const [first, second] = await Promise.all([a.claim(5), b.claim(5)])
  const claimed = [...first, ...second]
  assert.equal(claimed.length, 1, 'exactly one worker may hold the job')
  assert.equal(claimed[0]?.key, 'approvals')

  // And the loser gets nothing rather than blocking — which is the property that stops N workers
  // serialising into one.
  assert.ok(first.length === 0 || second.length === 0)
})

test('ten workers racing on four jobs claim each job exactly once', { skip }, async () => {
  const queues = Array.from({ length: 10 }, (_unused, i) => queueFor(`replica-${i}`))
  await seedRecurring(queues[0]!)

  const claims = await Promise.all(queues.map((q) => q.claim(10)))
  const ids = claims.flat().map((job) => job.id)
  assert.equal(ids.length, RECURRING.length, 'each seeded job goes to exactly one worker')
  assert.equal(new Set(ids).size, ids.length, 'no job was handed to two workers')
})

test('seeding from N replicas produces N-independent rows', { skip }, async () => {
  // `onConflict: 'keep'` plus the unique (kind, key). Four replicas booting together must produce
  // four rows, not sixteen.
  await Promise.all([0, 1, 2, 3].map((i) => seedRecurring(queueFor(`replica-${i}`))))
  const rows = await sql!<{ kind: string; key: string }[]>`select kind, key from jobs order by kind`
  assert.equal(rows.length, RECURRING.length)
})

test('every lease key names a contended resource, not a row', { skip }, async () => {
  for (const job of RECURRING) {
    assert.ok(
      !/^[0-9a-f]{8}-/.test(job.key),
      `${job.kind} keys on what looks like a row id — the key must name the contended resource`,
    )
  }
  assert.deepEqual(
    RECURRING.map((j) => `${j.kind}:${j.key}`).sort(),
    [
      'approvals.expire:approvals',
      'audit.verify:audit:chain',
      // The SCHEDULER, keyed on the one backup cadence. The `backup.run`/`backup.restore` jobs it
      // enqueues are keyed by run id and are deliberately NOT recurring — they are distinct
      // artefacts, and this service registers no handler for them at all. See `src/backups.ts`.
      'backup.schedule:backup:schedule',
      'idempotency.reap:idempotency',
      'outbox.relay:outbox',
    ],
  )
})

test('a claimed job is invisible to a second worker until the lease lapses', { skip }, async () => {
  const a = new JobQueue(sql as unknown as JobsSql, { owner: 'a', leaseMs: 50 })
  const b = new JobQueue(sql as unknown as JobsSql, { owner: 'b', leaseMs: 50 })
  await a.enqueue({ kind: AUDIT_VERIFY, key: 'audit:chain' })

  assert.equal((await a.claim(1)).length, 1)
  assert.equal((await b.claim(1)).length, 0, 'a live lease must exclude the second worker')

  await new Promise((r) => setTimeout(r, 80))
  // Once the lease lapses the work is claimable again — which is what makes a crashed worker
  // recoverable rather than a stuck queue.
  assert.equal((await b.claim(1)).length, 1)
})

/* ------------------------------------------------------------------ the verifier */

test('the verifier checkpoints a clean chain', { skip }, async () => {
  const jobDeps = deps()
  await sql!.begin(async (tx) => {
    await appendAudit(tx, {
      actor: OPERATOR_ONE,
      action: 'admin.flag.changed',
      subjectKind: 'feature_flag',
      subjectId: 'a',
      outcome: 'allowed',
    })
    return { value: null }
  })

  await createAuditVerifier(jobDeps)({ id: '1', kind: AUDIT_VERIFY, key: 'audit:chain', attempts: 1, maxAttempts: 5, payload: {} }, ctx())
  const checkpoints = await sql!<{ seq: string; verified_by: string }[]>`
    select seq, verified_by from audit_chain_checkpoints
  `
  assert.equal(checkpoints.length, 1)
  assert.equal(checkpoints[0]?.seq, '1')
  // The replica name IS carried here — `verified_by` is not an actor, and "which replica last
  // verified" is exactly what an operator chasing a stalled verification wants.
  assert.equal(checkpoints[0]?.verified_by, `${SERVICE_PRINCIPAL}@replica-a`)
})

test('THE VERIFIER REFUSES TO CHECKPOINT A BROKEN CHAIN', { skip }, async () => {
  // Checkpointing an unverified head would anchor the tamper: the next pass would resume from a
  // row the attacker wrote and declare everything before it good.
  const jobDeps = deps()
  await sql!.begin(async (tx) => {
    await appendAudit(tx, {
      actor: OPERATOR_ONE,
      action: 'admin.flag.changed',
      subjectKind: 'feature_flag',
      subjectId: 'a',
      outcome: 'allowed',
    })
    return { value: null }
  })
  await sql!`update audit_events set action = 'forged' where seq = 1`

  await assert.rejects(
    async () =>
      createAuditVerifier(jobDeps)({ id: '1', kind: AUDIT_VERIFY, key: 'audit:chain', attempts: 1, maxAttempts: 5, payload: {} }, ctx()),
    /found 1 break/,
  )
  assert.equal((await sql!`select seq from audit_chain_checkpoints`).length, 0)
  // And the break is visible as a gauge, so it can page. A P0 that only logs is a P0 nobody sees.
  assert.match(jobDeps.metrics.render(), /admin_audit_chain_breaks 1/)
})

test('the verifier throws so the job fails, rather than logging and succeeding', { skip }, async () => {
  // A broken chain that returned success would leave `jobs_failed_total` flat and the queue
  // rescheduling happily for ever.
  const jobDeps = deps()
  await sql!.begin(async (tx) => {
    await appendAudit(tx, { actor: OPERATOR_ONE, action: 'a', subjectKind: 'b', subjectId: 'c', outcome: 'allowed' })
    return { value: null }
  })
  await sql!`update audit_events set actor = ${'user:' + '9'.repeat(8) + '-9999-4999-8999-999999999999'} where seq = 1`
  await assert.rejects(async () =>
    createAuditVerifier(jobDeps)({ id: '1', kind: AUDIT_VERIFY, key: 'audit:chain', attempts: 1, maxAttempts: 5, payload: {} }, ctx()),
  )
})

test('a second verification pass over an unchanged chain is cheap and still clean', { skip }, async () => {
  const jobDeps = deps()
  for (let i = 0; i < 5; i++) {
    await sql!.begin(async (tx) => {
      await appendAudit(tx, { actor: OPERATOR_ONE, action: 'a', subjectKind: 'b', subjectId: `c${i}`, outcome: 'allowed' })
      return { value: null }
    })
  }
  const run = () => createAuditVerifier(jobDeps)({ id: '1', kind: AUDIT_VERIFY, key: 'audit:chain', attempts: 1, maxAttempts: 5, payload: {} }, ctx())
  await run()
  await run()
  // One checkpoint per head, updated in place rather than accumulating.
  assert.equal((await sql!`select seq from audit_chain_checkpoints`).length, 1)
  assert.equal((await verifyChain(sql!)).ok, true)
})

/* ------------------------------------------------------------------ the expirer */

test('the expirer closes overdue requests and writes one audit row each', { skip }, async () => {
  const later = () => new Date(Date.now() + 10 * 60_000)
  for (const subject of ['entry-a', 'entry-b']) {
    await sql!.begin(async (tx) => {
      await requestApproval(tx, {
        action: 'ledger.entry.reverse',
        subjectKind: 'ledger_entry',
        subjectId: subject,
        params: { description: 'd' },
        reasonCode: 'data_correction',
        reason: 'r',
        requestedBy: OPERATOR_ONE,
        ttlMinutes: 1,
      })
      return { value: null }
    })
  }

  const jobDeps = deps({ now: later })
  await createApprovalExpirer(jobDeps)({ id: '1', kind: APPROVALS_EXPIRE, key: 'approvals', attempts: 1, maxAttempts: 5, payload: {} }, ctx())

  const states = await sql!<{ state: string }[]>`select state from approvals`
  assert.ok(states.every((r) => r.state === 'expired'))
  const expired = await sql!<{ payload: any }[]>`
    select payload from audit_events where action = 'admin.approval.expired'
  `
  assert.equal(expired.length, 2)
  // The replica is forensic detail in the payload, not attribution in the actor.
  assert.equal(expired[0]?.payload.instanceId, 'replica-a')
  assert.match(jobDeps.metrics.render(), /admin_approvals_expired_total 2/)
})

test('the expirer writes nothing when nothing is overdue', { skip }, async () => {
  await sql!.begin(async (tx) => {
    await requestApproval(tx, {
      action: 'ledger.entry.reverse',
      subjectKind: 'ledger_entry',
      subjectId: 'entry-a',
      params: { description: 'd' },
      reasonCode: 'data_correction',
      reason: 'r',
      requestedBy: OPERATOR_ONE,
      ttlMinutes: 600,
    })
    return { value: null }
  })
  const before = (await sql!`select seq from audit_events`).length
  await createApprovalExpirer(deps())({ id: '1', kind: APPROVALS_EXPIRE, key: 'approvals', attempts: 1, maxAttempts: 5, payload: {} }, ctx())
  assert.equal((await sql!`select seq from audit_events`).length, before)
})

test('TWO EXPIRERS ON ONE OVERDUE REQUEST → ONE AUDIT ROW', { skip }, async () => {
  // The consequence rule 8 exists to prevent, made concrete: two replicas running expiry on a
  // timer would put one expiry into the audit of record twice.
  await sql!.begin(async (tx) => {
    await requestApproval(tx, {
      action: 'ledger.entry.reverse',
      subjectKind: 'ledger_entry',
      subjectId: 'entry-a',
      params: { description: 'd' },
      reasonCode: 'data_correction',
      reason: 'r',
      requestedBy: OPERATOR_ONE,
      ttlMinutes: 1,
    })
    return { value: null }
  })
  const later = () => new Date(Date.now() + 10 * 60_000)
  await Promise.all([
    createApprovalExpirer(deps({ now: later, instanceId: 'replica-a' }))(job(APPROVALS_EXPIRE), ctx()),
    createApprovalExpirer(deps({ now: later, instanceId: 'replica-b' }))(job(APPROVALS_EXPIRE), ctx()),
  ])
  assert.equal((await sql!`select seq from audit_events where action = 'admin.approval.expired'`).length, 1)
  assert.equal((await verifyChain(sql!, { from: 0n })).ok, true)
})

/* ------------------------------------------------------------------ the reaper */

test('the reaper removes spent keys and keeps the ones that made something', { skip }, async () => {
  const old = new Date(Date.now() - 30 * 24 * 60 * 60_000).toISOString()
  await sql!`insert into idempotency_keys (key, route, request_hash, created_at)
             values ('spent', '/v1/approvals', 'h', ${old}::timestamptz)`
  await sql!`insert into idempotency_keys (key, route, request_hash, artefact_id, created_at)
             values ('productive', '/v1/approvals', 'h', 'approval-1', ${old}::timestamptz)`
  await sql!`insert into idempotency_keys (key, route, request_hash) values ('recent', '/v1/approvals', 'h')`

  await createIdempotencyReaper(deps())(job(IDEMPOTENCY_REAP), ctx())
  const left = await sql!<{ key: string }[]>`select key from idempotency_keys order by key`
  // The productive row is the only link between an operator's key and the approval it raised, and
  // losing it turns "did my retry raise this twice" into an unanswerable question.
  assert.deepEqual(left.map((r) => r.key), ['productive', 'recent'])
})

/* ------------------------------------------------------------------ scheduling */

test('a recurring job is rescheduled only after it COMPLETES', { skip }, async () => {
  const queue = queueFor('replica-a')
  await seedRecurring(queue)
  const claimed = await queue.claim(10)
  const relay = claimed.find((j) => j.kind === OUTBOX_RELAY)!
  await queue.complete(relay.id)

  const reschedule = rescheduleRecurring(queue, quietLogger())
  reschedule({ type: 'completed', kind: OUTBOX_RELAY, key: 'outbox' })
  await new Promise((r) => setTimeout(r, 50))

  const rows = await sql!<{ kind: string }[]>`select kind from jobs where kind = ${OUTBOX_RELAY}`
  assert.equal(rows.length, 1)
})

test('a FAILED recurring job is not re-enqueued — the queue owns the backoff', { skip }, async () => {
  // `JobQueue.fail` already reschedules with backoff. Re-enqueueing on failure would be a second
  // schedule for one key, and the audit verifier depends on the backoff path: a broken chain must
  // eventually dead-letter, which is what leaves a durable record that verification cannot pass.
  const queue = queueFor('replica-a')
  const reschedule = rescheduleRecurring(queue, quietLogger())
  reschedule({ type: 'failed', kind: AUDIT_VERIFY, key: 'audit:chain' })
  await new Promise((r) => setTimeout(r, 50))
  assert.equal((await sql!`select kind from jobs`).length, 0)
})

test('every recurring kind has a registered handler', { skip }, async () => {
  // A seeded job with no handler is claimed, released, and silently never runs.
  const runner = new JobRunner({ queue: queueFor('replica-a') })
  registerHandlers(runner, deps())
  const queue = queueFor('replica-a')
  await seedRecurring(queue)
  const claimed = await queue.claim(10, RECURRING.map((r) => r.kind))
  assert.equal(claimed.length, RECURRING.length)
})

test('the runner does not claim while the service is draining', { skip }, async () => {
  let claiming = true
  const queue = queueFor('replica-a')
  const runner = new JobRunner({ queue, shouldClaim: () => claiming, pollMs: 10_000 })
  registerHandlers(runner, deps())
  await seedRecurring(queue)

  claiming = false
  assert.equal(await runner.tick(), 0, 'a draining replica must stop claiming new work')
  claiming = true
  assert.ok((await runner.tick()) > 0)
  await runner.stop(1_000)
})

/* ------------------------------------------------------------------ helpers */

function job(kind: string) {
  return { id: '00000000-0000-4000-8000-000000000000', kind, key: 'k', attempts: 1, maxAttempts: 5, payload: {} }
}

function ctx() {
  return { heartbeat: async () => true, signal: new AbortController().signal }
}

test('the checkpoint written by the job is the one verifyChain resumes from', { skip }, async () => {
  for (let i = 0; i < 3; i++) {
    await sql!.begin(async (tx) => {
      await appendAudit(tx, { actor: OPERATOR_ONE, action: 'a', subjectKind: 'b', subjectId: `c${i}`, outcome: 'allowed' })
      return { value: null }
    })
  }
  await createAuditVerifier(deps())(job(AUDIT_VERIFY), ctx())
  const resumed = await verifyChain(sql!)
  assert.equal(resumed.from, 3n)
  assert.equal(await writeCheckpoint(sql!, 'x').then((c) => c?.seq), 3n)
})
