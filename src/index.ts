/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this
 * file.
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a
 * separate one-shot process — AD-17 and rule 7. Here that matters twice over: below
 * `SCHEMA_VERSION` the `audit_events_chain_uniq` constraint may not exist, so two concurrent
 * appenders could fork the estate's audit of record without either failing, and neither may
 * `approvals_no_self_approval`, so one operator could approve their own ledger reversal. A service
 * that could create those at boot is a service that could start without them, and both of them are
 * controls rather than conveniences.
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module —
 * `NODE_OPTIONS=--import @opentelemetry/auto-instrumentations-node/register` in the deploy, which
 * reads `OTEL_EXPORTER_OTLP_ENDPOINT` and friends from the environment itself. That is why no
 * `OTEL_*` variable appears in `src/env.ts`.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql as DbSql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, httpProbe, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics } from './server.ts'
import { registerHandlers, rescheduleRecurring, seedRecurring } from './jobs.ts'
import { httpBillingClient, httpLedgerClient, httpMarketClient, probeReadiness } from './upstreams.ts'
import type { Db } from './outbox.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable.

// 2. Telemetry, before anything that can fail. A logger that exists before the pool means the
//    pool's failure is a structured, searchable, redacted line rather than a bare V8 stack the
//    collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
logger.info('starting', {
  version: env.version,
  schemaVersion: SCHEMA_VERSION,
  approvalTtlMinutes: env.approvalTtlMinutes,
})

// 3. The database pool. Opened before the schema assertion for the obvious reason that the
//    assertion is a query, and before the Lifecycle because the readiness probe closes over it.
const sql = postgres(env.databaseUrl, {
  max: env.databasePoolMax,
  // postgres.js writes notices to stderr as unstructured text by default, which is how a
  // connection string ends up in a log the collector cannot parse.
  onnotice: () => {},
})

// 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point: see
//    the file header for the two constraints a lower version would be missing.
try {
  await assertSchemaAtLeast(sql as unknown as DbSql, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The upstreams, before the Lifecycle so its probes can close over their URLs. Each takes this
//    service's own scoped token — never a shared one (SD-05) — and each uses it only where the
//    upstream refuses an operator's own bearer. See the header of `upstreams.ts`.
const serviceToken = () => env.serviceToken
const clientConfig = { deadlineMs: env.upstreamDeadlineMs, serviceToken }
const ledger = httpLedgerClient({ baseUrl: env.ledgerUrl, ...clientConfig })
const market = httpMarketClient({ baseUrl: env.marketUrl, ...clientConfig })
const billing = httpBillingClient({ baseUrl: env.billingUrl, ...clientConfig })

/** Every upstream the estate view reports on, with its `/readyz` probe. */
const readiness = [
  { name: 'identity', url: env.identityUrl },
  { name: 'ledger', url: env.ledgerUrl },
  { name: 'market', url: env.marketUrl },
  { name: 'billing', url: env.billingUrl },
].map((entry) => ({
  name: entry.name,
  probe: () => probeReadiness(entry.name, { baseUrl: entry.url, ...clientConfig }),
}))

// 6. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report.
const lifecycle = new Lifecycle({
  drainDelayMs: 5_000,
  // Generous, because a drain must not cut an execution between the upstream call and
  // `recordExecution`. That gap is the one place an action can run with nothing in this service
  // saying so — and this service is the thing that says so for the whole estate.
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})

lifecycle
  .addProbe(
    postgresProbe('postgres', (signal) =>
      Promise.race([
        sql`select 1`,
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
        }),
      ]),
    ),
  )
  // ══════════════════════════════════════════════════════════════════════════════════════════
  // **POSTGRES AND IDENTITY ARE HARD. EVERY OTHER UPSTREAM IS SOFT, AND THE SPLIT IS NOT A
  // JUDGEMENT CALL.**
  //
  // Postgres is hard because the audit chain lives in it and NOTHING this service exists to do
  // may happen without an audit row (SD-15). A replica that cannot write audit is a replica that
  // must refuse every operator action, so it should leave the balancer.
  //
  // Identity is hard because every route here requires a verified operator token, and this
  // service holds no fallback credential. `@cloudsforge/auth` correctly answers 503 rather than
  // 401 when the JWKS is unreachable, so a replica in that state serves nothing but 503s.
  //
  // Ledger, market and billing are SOFT precisely because of the tile design: with any of them
  // down the console still renders, one tile marked, and an operator can still read the audit
  // mirror, the approval queue and the broadcasts. Marking them hard would take the operator
  // console out of rotation for the duration of somebody else's incident — which is exactly the
  // moment it is needed, and exactly the failure mode this estate already has.
  // ══════════════════════════════════════════════════════════════════════════════════════════
  .addProbe(httpProbe('identity-jwks', env.identityJwksUrl, { kind: 'hard' }))
  .addProbe(httpProbe('ledger', `${env.ledgerUrl}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('market', `${env.marketUrl}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('billing', `${env.billingUrl}/livez`, { kind: 'soft' }))

// 7. The queue, built once and shared.
const db = sql as unknown as Db
const queue = new JobQueue(sql as unknown as JobsSql, {
  owner: env.instanceId,
  // Longer than the default 60 seconds because a full audit-chain verification over a year of
  // rows is the slowest handler here, and a lease that expires mid-walk would hand the same chain
  // to a second replica which would then write a competing checkpoint.
  leaseMs: 300_000,
})

// 8. Routes. After the Lifecycle so the health handlers report real state, and after the pool so
//    the stores are real rather than a lazily-connected surprise on the first request.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const server = createServer({
  lifecycle,
  logger,
  metrics,
  verifier,
  sql: db,
  producer: SERVICE,
  ledger,
  market,
  billing,
  readiness,
  // The same secret signs what this service emits and VERIFIES the audit rows every other service
  // mirrors here. See the header of `server.ts`: an unsigned audit intake is a forgery endpoint.
  eventSigningSecret: env.outboxSigningSecret,
  approvalTtlMinutes: env.approvalTtlMinutes,
  // Queue depth is sampled at scrape time rather than on a timer. There is no `setInterval` in
  // this repository, and CI greps for one — rule 8.
  beforeScrape: async () => {
    const stats = await queue.stats()
    metrics.set('jobs_pending', stats.pending)
    metrics.set('jobs_overdue', stats.overdue)
  },
})

// 9. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving.
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 2,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
      }
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})

registerHandlers(runner, {
  sql: db,
  logger,
  metrics,
  signingSecret: env.outboxSigningSecret,
  instanceId: env.instanceId,
  auditVerifyBatch: env.auditVerifyBatch,
  idempotencyTtlDays: env.idempotencyTtlDays,
})
await seedRecurring(queue)
runner.start()

// 10. Listen. Last of the construction steps, because a socket that accepts before its
//     dependencies exist is a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 11. Ready. Only now does `/readyz` start answering 200 and the balancer send traffic.
lifecycle.markReady()

// 12. Signal handlers, last of all. Hooks run in reverse registration order, so the server closes
//     first, then the runner stops claiming and DRAINS, then the pool closes with nothing left to
//     use it.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      // Idle keep-alive sockets hold the server open past the drain budget.
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
