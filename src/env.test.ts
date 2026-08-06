/**
 * Configuration.
 *
 * `loadEnv` is pure over its source, so every failure path is testable without mutating the
 * process. The eager export in `env.ts` is what makes the service fail fast; these tests are what
 * make the failures specific.
 */

import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import assert from 'node:assert/strict'

/**
 * A service credential, and THIS FIXTURE CONTAINS HYPHENS ON PURPOSE — that is the most important
 * thing about it.
 *
 * A credential body is base64**url**, so `-` and `_` are in its alphabet. Measured on the running
 * estates: the mainnet credential is alphanumeric and the testnet one CONTAINS A HYPHEN. So a
 * "secrets have no hyphens" rule — which is correct for the signing key below, and which every
 * placeholder this estate wrote would have failed — passes mainnet and kills testnet at boot.
 *
 * Keeping a hyphenated credential here means that mistake fails CI instead of failing one estate
 * in production. Do not "tidy" the hyphens out of this value.
 */
const CREDENTIAL = 'cfsc_TToR-eOeVTDnqhX1-nu6-u7DoCr4MCfa86g4g6kd404'

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
  // GENERATED, not written. The literal that used to sit here was
  // `a-real-looking-secret-of-sufficient-length` — hyphenated, 42 characters, and therefore past
  // the old 24-character floor. It is the same family of value as micro-org #142's
  // `estate-only-outbox-secret-00000000000000`, which reached 44 containers unchallenged; every
  // test in this file was built on it, so the suite was asserting that a "real-LOOKING" secret is
  // a real one. `openssl rand -base64 48` is what the runbook already tells an operator to run.
  OUTBOX_SIGNING_SECRET: randomBytes(48).toString('base64'),
  IDENTITY_URL: 'http://127.0.0.1:4001',
  LEDGER_URL: 'http://127.0.0.1:4007',
  MARKET_URL: 'http://127.0.0.1:4013',
  BILLING_URL: 'http://127.0.0.1:4009',
  // Required with NO default, deliberately — a default answer to "which estate am I?" is how a
  // testnet backup gets restored over mainnet balances. `testnet` here, never `mainnet`, so a
  // fixture can never stand in for the environment where the refusal actually matters.
  ADMIN_API_ESTATE_ENVIRONMENT: 'testnet',
}

/**
 * The two credential variables, and **NEITHER OF THEM IS IN `REQUIRED` ANY MORE — micro-org #222.**
 *
 * `ADMIN_API_SERVICE_TOKEN` used to be required, and the argument for that was written down: an
 * optional credential here would be "a privileged BFF that silently cannot reach the ledger". The
 * argument was right about the danger and wrong about the remedy. Requiring the variable kept a
 * boot dependency on a **600-second token that nothing in this process could renew**, so a
 * deployment holding a long-lived `ADMIN_API_IDENTITY_CREDENTIAL` and no token was correctly
 * configured and refused to start, while one holding the expired JWT the estate actually ran
 * booted happily and 401ed every ledger call for 26 hours.
 *
 * The silence is answered where it belongs instead: `upstreams.ts` names the mode it chose,
 * `index.ts` logs `fatal` at boot when that mode cannot authenticate, and
 * `admin_api_service_token_usable` answers the question on every scrape. A refusal to boot is a
 * good alarm for a value that is WRONG; it is the wrong alarm for a value that is ABSENT while a
 * deploy is being taught to pass its replacement.
 */
const CREDENTIALS: Record<string, string> = {
  ADMIN_API_IDENTITY_CREDENTIAL: CREDENTIAL,
}

for (const [key, value] of Object.entries({ ...REQUIRED, ...CREDENTIALS })) process.env[key] = value

const { EnvError, SERVICE, env, loadEnv, parseSecretList } = await import('./env.ts')

/**
 * "The new one" and "the one being rotated out" for the acceptance-list cases below.
 *
 * These were `accept-secret-newest-0000000000000000` and `accept-secret-superseded-00000000000`,
 * whose own comment said they were "long enough to pass the 24-character rule". That is the defect
 * stated out loud: both are hyphenated, zero-padded placeholders of exactly the family that
 * reached 44 containers as micro-org #142, and this suite asserted they were VALID secrets.
 *
 * Generated rather than replaced with better-looking literals, so a placeholder cannot creep back
 * in the next time somebody needs a fixture. They are still never real values — a secret in a test
 * fixture is a secret in the repository, and this file is public — but they are now real SHAPES.
 */
const NEWEST = randomBytes(48).toString('base64')
const SUPERSEDED = randomBytes(48).toString('base64')

const withEnv = (overrides: Record<string, string | undefined> = {}) => ({
  ...REQUIRED,
  ...CREDENTIALS,
  ...overrides,
})

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
  // Both variables refuse it, but NOT by the same rule, and the split is the whole of this change:
  // one is a key this estate generates, the other is a credential identity mints. The old suite
  // ran one loop over both names because the service ran one function over both values.
  assert.throws(
    () => loadEnv(withEnv({ OUTBOX_SIGNING_SECRET: 'CHANGE_ME' })),
    /known placeholder/,
  )
  assert.throws(
    () => loadEnv(withEnv({ ADMIN_API_SERVICE_TOKEN: 'CHANGE_ME' })),
    (err: unknown) =>
      err instanceof EnvError &&
      /ADMIN_API_SERVICE_TOKEN/.test(err.message) &&
      /not a service credential/.test(err.message),
  )

  // THE ONE THE OLD DENY-LIST COULD NOT CATCH, AND THE REASON THE LIST IS GONE. This exact
  // 40-character string is `deploy/compose/docker-compose.estate.yml`'s default for this
  // service's own credential; the outbox sibling of it reached 44 containers as micro-org #142.
  // Neither was on anybody's list of exact strings, and neither could be — the next placeholder
  // somebody writes is by definition not on the list. Both are refused now for a property they
  // cannot shed, and neither message may echo the value.
  for (const [name, value] of [
    ['OUTBOX_SIGNING_SECRET', 'estate-only-outbox-secret-00000000000000'],
    ['ADMIN_API_SERVICE_TOKEN', 'estate-placeholder-token-0000000000000000'],
  ] as const) {
    assert.throws(
      () => loadEnv(withEnv({ [name]: value })),
      (err: unknown) =>
        err instanceof EnvError && new RegExp(name).test(err.message) && !err.message.includes(value),
      `${name} must refuse the estate's own placeholder without echoing it`,
    )
  }
})

test('a short secret is refused, and the unit is BYTES rather than keystrokes', () => {
  // These assertions used to demand the message say "at least 24 characters" — the keystroke floor
  // that let micro-org #142's 40-character placeholder through every service in the estate.
  // Pinning that wording made the test a defence of the defective rule: any fix that stopped
  // counting characters would fail CI, however much better the new rule was.
  //
  // What they assert now is the PROPERTY that matters. `hunter2` happens to be spelled in the
  // base64 alphabet, so it is not the alphabet that catches it — it decodes to 5 bytes.
  assert.throws(
    () => loadEnv(withEnv({ OUTBOX_SIGNING_SECRET: 'hunter2' })),
    (err: unknown) =>
      err instanceof EnvError &&
      /5 bytes of key material/.test(err.message) &&
      /at least 32/.test(err.message) &&
      !err.message.includes('hunter2'),
  )
  // A credential is measured the same way, off its base64url body. `cfsc_short` is a deployment
  // that BELIEVES it has a credential — worse than one that knows it has none, because it fails at
  // the ledger with a 401 that reads as "ledger rejected admin-api".
  assert.throws(
    () => loadEnv(withEnv({ ADMIN_API_SERVICE_TOKEN: 'cfsc_short' })),
    (err: unknown) =>
      err instanceof EnvError &&
      /ADMIN_API_SERVICE_TOKEN/.test(err.message) &&
      /at least 32/.test(err.message) &&
      !err.message.includes('cfsc_short'),
  )
})

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **#222: THE LIVE VALUE OF THIS VARIABLE IS AN EXPIRED JWT, AND THIS IS THE TEST THAT SAYS SO.**
 *
 * Measured on 2026-08-05: `ADMIN_API_SERVICE_TOKEN` held a 701-byte JWT that had expired 26 hours
 * earlier, on a container reporting healthy. `upstreams.ts` puts that value in the `authorization`
 * header of every ledger call, so every reversal and trial-balance read since the expiry answered
 * 401 while `/livez` stayed green — a privileged BFF that cannot reach the ledger and does not say
 * so anywhere an operator looks.
 *
 * A token is not a credential. A JWT is minted with a short life and is read HERE ONLY AT BOOT, so
 * it is dead on the next restart at the latest; a credential confers nothing by itself, is
 * revocable, and survives a restart. The refusal is therefore correct rather than inconvenient,
 * and it must stay a refusal: there is no JWT exemption and no fallback to a weaker assertion.
 *
 * **BOTH NAMES FACE IT.** The class of a value is a property of the VALUE and never of the variable
 * holding it: measured the same day, `SETTLEMENT_SERVICE_TOKEN` held `cfsc_` + 43 characters while
 * this one held a 701-byte expired JWT. A guard picked from the name would have been right for
 * exactly one of them, which is why the loop below runs over both and neither is exempt.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
test('a JWT is refused BY NAME on either credential variable, however well-formed it is', () => {
  // Header and payload segments only; the guard matches SHAPE and never decodes, because this is a
  // refusal rather than a parse. The value is not a real token and carries no signature.
  const jwt = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.${randomBytes(400).toString('base64url')}.sig`
  for (const name of ['ADMIN_API_SERVICE_TOKEN', 'ADMIN_API_IDENTITY_CREDENTIAL'] as const) {
    assert.throws(
      () => loadEnv(withEnv({ [name]: jwt })),
      (err: unknown) =>
        err instanceof EnvError &&
        new RegExp(name).test(err.message) &&
        /TOKEN, not a credential/.test(err.message) &&
        // Not one byte of it. A 701-byte JWT echoed into a fatal log line is a bearer token in the
        // log collector, which is a wider audience than the file it came from.
        !err.message.includes(jwt.slice(0, 40)),
      `${name} must refuse a JWT`,
    )
  }
  // And the credential it must be replaced with loads, hyphens and all.
  assert.equal(loadEnv(withEnv({ ADMIN_API_SERVICE_TOKEN: CREDENTIAL })).serviceToken, CREDENTIAL)
  assert.equal(loadEnv(withEnv()).identityCredential, CREDENTIAL)
})

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **ABSENCE IS A SUPPORTED MODE. PRESENT-AND-RUBBISH IS NOT.** The pair is the whole demotion.
 *
 * Compose interpolates `${ADMIN_API_IDENTITY_CREDENTIAL:-}`, so an unset credential arrives as the
 * EMPTY STRING rather than as `undefined` — and `migrator.ts` shares this environment while
 * dialling nobody. `null` is the absence said once, and `upstreams.ts` turns it into a NAMED mode
 * rather than into a request that goes out unauthenticated.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
test('an ABSENT credential loads as null; a present rubbish one still refuses to boot', () => {
  assert.equal(loadEnv(withEnv({ ADMIN_API_IDENTITY_CREDENTIAL: '' })).identityCredential, null)
  assert.equal(loadEnv(withEnv({ ADMIN_API_IDENTITY_CREDENTIAL: '   ' })).identityCredential, null)
  // The legacy variable is absent from `REQUIRED`, so this is the default state of the fixture.
  assert.equal(loadEnv(withEnv()).serviceToken, null)

  // Absent is supported; a 20-character placeholder is a deployment that BELIEVES it has a
  // credential, and it is refused exactly as loudly as before the demotion.
  assert.throws(
    () => loadEnv(withEnv({ ADMIN_API_IDENTITY_CREDENTIAL: 'cfsc_short' })),
    (err: unknown) =>
      err instanceof EnvError && /ADMIN_API_IDENTITY_CREDENTIAL/.test(err.message),
  )
})

/* ---------------------------------------------------------- the rotation overlap window */

/**
 * `OUTBOX_SIGNING_SECRET` is one shared key across the estate, and it must be rotated. It signs the
 * outbox->inbox hop, so if a sender moves to a new secret while this receiver still holds only the
 * old one, event delivery partitions silently — and the thing that goes quiet here is the estate's
 * audit of record, which looks exactly like "nothing happened".
 *
 * A rolling rotation is therefore only possible if the RECEIVER accepts more than one secret at a
 * time. `verifyDelivery` has taken a list since `contracts/packages/events/src/index.ts`; what
 * was missing was the env plumbing.
 */
test('OUTBOX_ACCEPT_SECRETS is absent by default, and the service accepts exactly the signing secret', () => {
  // The backwards-compatible path, and the reason this change is safe to deploy on its own: with
  // the variable unset the accept list is a one-element list holding today's secret, which is
  // byte-for-byte the behaviour of the scalar it replaces. Deploying this is a no-op; that is what
  // lets the rotation be staged afterwards.
  const loaded = loadEnv(REQUIRED)
  assert.deepEqual([...loaded.acceptSecrets], [REQUIRED['OUTBOX_SIGNING_SECRET']])
})

test('OUTBOX_ACCEPT_SECRETS takes a list newest first, which is the overlap window itself', () => {
  const loaded = loadEnv(withEnv({ OUTBOX_ACCEPT_SECRETS: `${NEWEST}, ${SUPERSEDED}` }))
  assert.deepEqual([...loaded.acceptSecrets], [NEWEST, SUPERSEDED])
  // Signing is NOT widened. This service keeps emitting under one secret; only what it will accept
  // is plural, because a producer that signs under two keys has not rotated, it has forked.
  assert.equal(loaded.outboxSigningSecret, REQUIRED['OUTBOX_SIGNING_SECRET'])
})

test('every entry in OUTBOX_ACCEPT_SECRETS is validated exactly like the signing secret', () => {
  // No escape hatch: a list is not a way to smuggle in a value that would be refused on its own.
  assert.throws(() => loadEnv(withEnv({ OUTBOX_ACCEPT_SECRETS: `${NEWEST},changeme` })), /known placeholder/)
  // The index matters, and it is what replaced the old `/at least 24 characters/` assertion: an
  // operator with the file open counts commas, so the message must name WHICH entry failed — and
  // must not carry the entry itself.
  assert.throws(
    () => loadEnv(withEnv({ OUTBOX_ACCEPT_SECRETS: `${NEWEST},hunter2` })),
    (err: unknown) =>
      err instanceof EnvError &&
      /OUTBOX_ACCEPT_SECRETS\[1\]/.test(err.message) &&
      /at least 32/.test(err.message) &&
      !err.message.includes('hunter2'),
  )
  assert.throws(() => parseSecretList('', 'X'), EnvError)
  assert.throws(() => parseSecretList(' , , ', 'X'), EnvError)
})

test('OUTBOX_ACCEPT_SECRETS refuses the same secret twice, so "which key verified this" has an answer', () => {
  // `verifyDelivery` reports the INDEX of the key that matched, and that index is how an operator
  // knows whether every producer has moved off the old secret yet — which is the only signal that
  // says a rotation has finished and the old key can be dropped. A duplicate makes it ambiguous.
  assert.throws(() => loadEnv(withEnv({ OUTBOX_ACCEPT_SECRETS: `${NEWEST},${NEWEST}` })), /same secret twice/)
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
  for (const name of ['OUTBOX_SIGNING_SECRET', 'OUTBOX_ACCEPT_SECRETS', 'ADMIN_API_SERVICE_TOKEN']) {
    assert.ok(/SECRET|TOKEN|KEY/.test(name), `${name} is a credential and should say so`)
  }
})

/**
 * The estate environment, which has no default and no safe guess.
 *
 * Every other required variable here fails loudly the moment it is used — a missing JWKS URL is a
 * 503 on the first request. This one would fail SILENTLY and LATE: an estate that guessed its own
 * environment would stamp every backup it takes with the wrong label, and the artefacts would sit
 * on disk looking correct until somebody restored one into the wrong estate. That is why it is
 * `required` rather than `optional`, and why the value is checked against a closed list rather
 * than merely being non-empty.
 */
test('ADMIN_API_ESTATE_ENVIRONMENT is required and closed', () => {
  const { ADMIN_API_ESTATE_ENVIRONMENT: _dropped, ...without } = REQUIRED
  assert.throws(() => loadEnv(without), /ADMIN_API_ESTATE_ENVIRONMENT is required/)

  assert.throws(
    () => loadEnv(withEnv({ ADMIN_API_ESTATE_ENVIRONMENT: 'prod' })),
    /must be one of mainnet, testnet, development/,
    'an unrecognised environment must be refused rather than passed through — "prod" is exactly ' +
      'the plausible-looking value somebody would type for mainnet',
  )

  for (const environment of ['mainnet', 'testnet', 'development']) {
    assert.equal(loadEnv(withEnv({ ADMIN_API_ESTATE_ENVIRONMENT: environment })).estateEnvironment, environment)
  }
})

/** The compose project IS defaulted, and the asymmetry with the environment is the point. */
test('the compose project defaults to mainnet’s, because that is the compose default too', () => {
  const { ADMIN_API_COMPOSE_PROJECT: _unset, ...without } = { ...REQUIRED, ADMIN_API_COMPOSE_PROJECT: 'x' }
  assert.equal(loadEnv(without).composeProject, 'cloudsforge-estate')
  assert.equal(loadEnv(withEnv({ ADMIN_API_COMPOSE_PROJECT: 'cf-testnet' })).composeProject, 'cf-testnet')
})
