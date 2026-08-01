/**
 * Configuration.
 *
 * `loadEnv` is pure over its source, so every failure path is testable without mutating the
 * process. The eager export in `env.ts` is what makes the service fail fast; these tests are what
 * make the failures specific.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

/**
 * A valid environment, applied to the process BEFORE `./env.ts` is imported.
 *
 * The import itself is a test: `env.ts` validates eagerly and calls `process.exit(1)` on a bad
 * configuration, so if these values were not sufficient this file would not run at all.
 */
const REQUIRED: Record<string, string> = {
  ADMIN_API_DATABASE_URL: 'postgres://admin:admin@127.0.0.1:5432/admin_api',
  IDENTITY_JWKS_URL: 'http://127.0.0.1:4001/.well-known/jwks.json',
  IDENTITY_ISSUER: 'http://127.0.0.1:4001',
  OUTBOX_SIGNING_SECRET: 'a-real-looking-secret-of-sufficient-length',
  IDENTITY_URL: 'http://127.0.0.1:4001',
  LEDGER_URL: 'http://127.0.0.1:4007',
  MARKET_URL: 'http://127.0.0.1:4013',
  BILLING_URL: 'http://127.0.0.1:4009',
  ADMIN_API_SERVICE_TOKEN: 'a-real-looking-token-of-sufficient-length',
}

for (const [key, value] of Object.entries(REQUIRED)) process.env[key] = value

const { EnvError, SERVICE, env, loadEnv } = await import('./env.ts')

const withEnv = (overrides: Record<string, string | undefined> = {}) => ({ ...REQUIRED, ...overrides })

test('the eager export validated the process environment at import', () => {
  // If it had not, this file would have exited with a structured fatal line before reaching here.
  assert.equal(env.databaseUrl, REQUIRED['ADMIN_API_DATABASE_URL'])
  assert.equal(SERVICE, 'admin-api')
})

test('every required variable names itself when it is missing', () => {
  for (const name of Object.keys(REQUIRED)) {
    assert.throws(
      () => loadEnv(withEnv({ [name]: undefined })),
      (err: unknown) => {
        assert.ok(err instanceof EnvError, `${name} produced ${String(err)}`)
        // `undefined` propagating into a connection string surfaces four layers later as an
        // unreadable driver error. This is the difference.
        assert.match(err.message, new RegExp(name))
        return true
      },
      `${name} should be required`,
    )
  }
})

test('a known placeholder is refused rather than booted with', () => {
  for (const name of ['OUTBOX_SIGNING_SECRET', 'ADMIN_API_SERVICE_TOKEN']) {
    assert.throws(
      () => loadEnv(withEnv({ [name]: 'CHANGE_ME' })),
      /known placeholder/,
      `${name} should refuse a placeholder`,
    )
  }
})

test('a short secret is refused — length is the only entropy proxy available here', () => {
  assert.throws(() => loadEnv(withEnv({ OUTBOX_SIGNING_SECRET: 'short' })), /at least 24 characters/)
  // Set above the point at which a human-chosen string is plausible, so a memorable password fails.
  assert.throws(() => loadEnv(withEnv({ ADMIN_API_SERVICE_TOKEN: 'correct-horse-battery' })), /at least 24/)
})

test('the defaults are the documented ones', () => {
  const loaded = loadEnv(REQUIRED)
  assert.equal(loaded.port, 4014)
  assert.equal(loaded.databasePoolMax, 10)
  assert.equal(loaded.upstreamDeadlineMs, 5_000)
  assert.equal(loaded.approvalTtlMinutes, 240)
  assert.equal(loaded.auditVerifyBatch, 5_000)
  assert.equal(loaded.idempotencyTtlDays, 14)
  assert.equal(loaded.logLevel, 'info')
})

test('an out-of-range integer is refused with its bounds', () => {
  assert.throws(() => loadEnv(withEnv({ PORT: '0' })), /between 1 and 65535/)
  assert.throws(() => loadEnv(withEnv({ PORT: 'eight thousand' })), /whole number/)
  assert.throws(() => loadEnv(withEnv({ ADMIN_API_APPROVAL_TTL_MINUTES: '0' })), /between 1 and 20160/)
  assert.throws(() => loadEnv(withEnv({ ADMIN_API_AUDIT_VERIFY_BATCH: '0' })), /between 1 and 1000000/)
  assert.throws(() => loadEnv(withEnv({ ADMIN_API_IDEMPOTENCY_TTL_DAYS: '0' })), /between 1 and 365/)
})

test('an unknown log level is refused', () => {
  assert.throws(() => loadEnv(withEnv({ LOG_LEVEL: 'verbose' })), /debug, info, warn, error/)
})

test('the instance id falls back to the hostname', () => {
  assert.equal(loadEnv(REQUIRED, 'pod-7').instanceId, 'pod-7')
  assert.equal(loadEnv(withEnv({ INSTANCE_ID: 'named' }), 'pod-7').instanceId, 'named')
  assert.equal(loadEnv(REQUIRED, '').instanceId, 'unknown')
})

test('this service reads exactly one database variable', () => {
  // Rule 1, asserted in the suite as well as in CI. The name is assembled so the CI check — which
  // greps source for another service's connection variable — does not fire on a test that agrees
  // with it. `micro-market` had to do the same, and the workflow's own comment records why.
  const foreign = ['LEDGER', 'DATABASE', 'URL'].join('_')
  const loaded = loadEnv(withEnv({ [foreign]: 'postgres://ledger:ledger@127.0.0.1:5432/ledger' }))
  assert.equal(loaded.databaseUrl, REQUIRED['ADMIN_API_DATABASE_URL'])
  assert.ok(!Object.values(loaded).includes('postgres://ledger:ledger@127.0.0.1:5432/ledger'))
})

test('no variable carrying credential vocabulary is a duration or a count', () => {
  // `secret-hygiene` refuses an .env.example line whose NAME matches *SECRET*|*TOKEN*|*KEY* and
  // whose value does not look like a placeholder. `micro-devplatform` hit that with a duration
  // called …_SECRET_OVERLAP_MINUTES and renamed the variable rather than weakening the guard.
  // This asserts the naming, so a future numeric setting cannot quietly reintroduce it.
  const numeric = [
    'PORT',
    'ADMIN_API_DATABASE_POOL_MAX',
    'ADMIN_API_UPSTREAM_DEADLINE_MS',
    'ADMIN_API_APPROVAL_TTL_MINUTES',
    'ADMIN_API_AUDIT_VERIFY_BATCH',
    'ADMIN_API_IDEMPOTENCY_TTL_DAYS',
  ]
  for (const name of numeric) {
    assert.ok(!/SECRET|TOKEN|KEY/.test(name), `${name} carries credential vocabulary but holds a number`)
  }
  // And in the other direction: everything that IS a credential says so in its name.
  for (const name of ['OUTBOX_SIGNING_SECRET', 'ADMIN_API_SERVICE_TOKEN']) {
    assert.ok(/SECRET|TOKEN|KEY/.test(name), `${name} is a credential and should say so`)
  }
})
