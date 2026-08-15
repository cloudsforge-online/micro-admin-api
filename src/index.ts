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
import { claimEstateIdentity } from './backups.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics } from './server.ts'
import { registerHandlers, rescheduleRecurring, seedRecurring } from './jobs.ts'
import { buildUpstreams, probeReadiness } from './upstreams.ts'
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
  estateEnvironment: env.estateEnvironment,
  composeProject: env.composeProject,
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

// 4b. Claim this estate's identity, or refuse to start.
//
//     ══════════════════════════════════════════════════════════════════════════════════════════
//     **THE BOOT REFUSAL THAT MAKES A CROSS-ENVIRONMENT RESTORE UNREACHABLE.**
//
//     `estate_identity` holds one immutable row saying which estate this database belongs to. It is
//     written here, once, on first boot. Every subsequent boot COMPARES rather than writes, and a
//     disagreement between the configured environment and the claimed one exits the process.
//
//     That turns two different mistakes into the same loud failure at the same early moment:
//     a container pointed at the wrong database, and a compose file labelled with the wrong
//     environment. On 2026-08-05 the second of those happened twice — the seeder ran against the
//     MAINNET project whatever it was asked for — and the same defect on a restore path overwrites
//     real balances. A backup is stamped with this value and a restore is refused on it by
//     `restore_runs_environment_matches()`, so a wrong value here poisons every artefact taken
//     afterwards. It is worth a refusal to serve.
//
//     Placed AFTER the schema assertion because `estate_identity` arrives in migration 10, and
//     BEFORE the routes because no request may be answered by a replica that does not know which
//     estate it is.
//     ══════════════════════════════════════════════════════════════════════════════════════════
try {
  const identity = await claimEstateIdentity(
    sql as unknown as Db,
    env.estateEnvironment,
    `service:${SERVICE}@${env.instanceId}`,
  )
  logger.info(identity.claimed ? 'estate identity claimed' : 'estate identity confirmed', {
    environment: identity.environment,
    composeProject: env.composeProject,
    claimedAt: identity.claimedAt,
  })
} catch (err) {
  logger.fatal('estate identity check failed — refusing to start', {
    err,
    configured: env.estateEnvironment,
  })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The upstreams, before the Lifecycle so its probes can close over their URLs. Each takes this
//    service's own scoped bearer — never a shared one (SD-05) — and each uses it only where the
//    upstream refuses an operator's own bearer. See the header of `upstreams.ts`.
//
//    ONE LINE, and the body of it lives in `upstreams.ts` where a test can reach it. What used to
//    be here was `const serviceToken = () => env.serviceToken` — a dead JWT read once at import,
//    presented verbatim for 26 hours, structurally invisible to every test in this repository
//    because they all build their own client. micro-org #222.
const upstreams = buildUpstreams(env, {
  onEvent: (event) => {
    if (event.kind === 'minted') {
      logger.info('service token minted', {
        service: event.service,
        expiresIn: event.expiresIn,
        refreshInMs: event.refreshInMs,
      })
    } else if (event.kind === 'exchange_failed') {
      // `warn`, not `fatal`, and only because of `hadUsableToken`: a failed exchange while a live
      // token is still held is the outage the provider is built to ride out, and paging on it
      // would page on every identity blip.
      logger.warn('service credential exchange failed', { ...event })
    }
  },
})
const { ledger, market, billing, identity, notify, nda, clientConfig } = upstreams

// ────────────────────────────────────────────────────────────────────────────────────────────────
// Said at boot, at the level its consequence deserves, because the alternative is what actually
// happened: an operator console that looks entirely healthy while every privileged action it can
// take has been answering 401 for a day.
// ────────────────────────────────────────────────────────────────────────────────────────────────
if (upstreams.mode === 'none') {
  logger.fatal('NO CREDENTIAL AT ALL — every ledger reversal and every role grant will fail', {
    remedy:
      'set ADMIN_API_IDENTITY_CREDENTIAL (long-lived, cfsc_…, from POST /service-credentials); ' +
      'estate-bootstrap.sh already mints it into tokens.env',
  })
} else if (upstreams.mode === 'static') {
  logger.fatal('EXPIRING TOKEN, NOT A CREDENTIAL — every service call will 401 about ten minutes from now', {
    whatWillHappen:
      'ADMIN_API_SERVICE_TOKEN lives 600s and nothing in this process can renew it. From minute ten ' +
      'the ledger refuses every approved reversal and every trial-balance read, and identity refuses ' +
      'every role grant — while /livez stays green, because it makes no outbound call.',
    remedy: 'set ADMIN_API_IDENTITY_CREDENTIAL in the deploy and remove ADMIN_API_SERVICE_TOKEN',
  })
} else {
  logger.info('service credential mode', { mode: upstreams.mode, identityUrl: env.identityUrl })
}

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
  notify,
  market,
  billing,
  identity,
  nda,
  readiness,
  // Signing stays singular (see the relay below); ACCEPTING is a list, so the estate's shared
  // secret can be rotated with an overlap window instead of a flag day. Unset, the list is exactly
  // `[OUTBOX_SIGNING_SECRET]`. See the header of `server.ts`: an unsigned audit intake is a forgery
  // endpoint, and a partitioned one is an audit of record that reads as "nothing happened".
  eventAcceptSecrets: env.acceptSecrets,
  approvalTtlMinutes: env.approvalTtlMinutes,
  estateEnvironment: env.estateEnvironment,
  composeProject: env.composeProject,
  // Queue depth is sampled at scrape time rather than on a timer. There is no `setInterval` in
  // this repository, and CI greps for one — rule 8.
  beforeScrape: async () => {
    const stats = await queue.stats()
    metrics.set('jobs_pending', stats.pending)
    metrics.set('jobs_overdue', stats.overdue)

    // ════════════════════════════════════════════════════════════════════════════════════════
    // **THE QUESTION THAT HAD NO ANSWER ANYWHERE WHILE THE TOKEN QUIETLY DIED FOR 26 HOURS:**
    // can this process authenticate to its peers right now?
    //
    // A GAUGE rather than a readiness probe, and that is a decision rather than an omission.
    // `serviceTokenProbe` exists in `@cloudsforge/auth` and is deliberately not wired, for the
    // reason market's `upstreams.ts` gives and which holds at least as strongly here:
    //
    //   1. **The console's read surface is served from this service's own tables.** The audit
    //      mirror, the approval queue, the flags and the broadcasts make no outbound call. A hard
    //      probe on the credential would take the OPERATOR CONSOLE out of the balancer over a
    //      variable those routes cannot touch — during, by definition, an incident.
    //   2. **Pulling the replica would fix nothing.** Every replica reads the same environment, so
    //      a probe decides which container refuses, not whether one does.
    //   3. The write paths that need the bearer already fail honestly at the point of use: a
    //      `ServiceTokenUnavailableError` is 503 rather than 401, so nothing tells an operator the
    //      ledger refused them when the truth is that nobody configured this service.
    //
    // Deliberately NOT "is a token present". An expired token is retained after it dies — that is
    // the most useful thing an operator can be shown — so presence would report healthy across
    // exactly the outage this exists to make visible.
    // ════════════════════════════════════════════════════════════════════════════════════════
    const snapshot = upstreams.identityTokens?.snapshot()
    metrics.set('admin_api_service_token_usable', snapshot?.hasUsableToken === true ? 1 : 0)
    if (snapshot?.expiresInSeconds !== undefined && snapshot.expiresInSeconds !== null) {
      // Goes steadily NEGATIVE while identity is unreachable, which is what says "identity has
      // been down for four minutes" where an absent token says nothing at all.
      metrics.set('admin_api_service_token_expires_in_seconds', snapshot.expiresInSeconds)
    }
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
  composeProject: env.composeProject,
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
