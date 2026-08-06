/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repo declares the variables it needs; the deploy provides
 * exactly those" — is a property of this file. Every variable this service reads is named here and
 * nowhere else, so the deploy manifest can be derived from it and `env_file: .env` fan-out (which
 * hands every container the whole estate's secrets) has nothing to justify it.
 *
 * Two behaviours are inherited from market, which took them from worlds, which took them from
 * custody:
 *
 *   1. **A missing variable names itself.** `undefined` propagating into a connection string
 *      surfaces four layers later as an unreadable driver error.
 *   2. **A placeholder is refused outright.** A default secret in source is not convenient, it is
 *      catastrophic, and a placeholder that boots is a placeholder that reaches production. What
 *      makes that refusal real rather than decorative is that `@cloudsforge/secrets` checks the
 *      SHAPE of a value rather than membership of a list of exact strings — see the block where
 *      this file's own `PLACEHOLDERS` set used to be.
 *
 * ## Why the upstream URLs are all required and none of them is optional
 *
 * This service composes an operator's view of the estate. A missing upstream URL would render as a
 * permanently unavailable tile, and an operator reading a console during an incident cannot tell a
 * tile that is down from a tile that was never configured. So every upstream this service knows
 * how to call is named at boot, and its absence is a boot failure rather than a silent hole in the
 * console. The tiles then degrade for the one reason a tile is allowed to degrade: the upstream is
 * actually unwell.
 *
 * ## Naming, and the guard that shaped it
 *
 * `secret-hygiene` refuses an `.env.example` line whose NAME matches `*SECRET*|*TOKEN*|*KEY*` and
 * whose value does not look like a placeholder. `micro-devplatform` hit this with a duration
 * called `…_SECRET_OVERLAP_MINUTES` and renamed the variable rather than weakening the guard. Two
 * durations here would have had the same problem — the approval TTL and the audit verification
 * window — and both are named `…_MINUTES` / `…_DAYS` with no credential vocabulary in them. The
 * only variables in this file carrying `TOKEN` or `SECRET` in their names are credentials.
 */

import { hostname } from 'node:os'
import {
  SecretError,
  assertGeneratedSecret,
  assertServiceCredential,
  parseSecretList as parseSharedSecretList,
} from '@cloudsforge/secrets'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a migration
 * advisory lock.
 */
export const SERVICE = 'admin-api'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

/**
 * THE `PLACEHOLDERS` SET THAT USED TO BE HERE IS GONE, AND ITS ABSENCE IS THE FIX.
 *
 * It held ten exact strings and was paired with a 24-character floor. Neither could fail for the
 * value that actually reached 44 containers on both networks: micro-org #142's
 * `estate-only-outbox-secret-00000000000000` is 40 characters and was on nobody's list — and
 * neither is `estate-placeholder-token-0000000000000000`, which is the default this repository's
 * OWN compose block gives `ADMIN_API_SERVICE_TOKEN` (`deploy/compose/docker-compose.estate.yml`).
 * A check that cannot fail is worse than no check, because the absence of an alarm gets read as
 * the absence of a problem — and this service is the estate's audit of record and its privileged
 * operator surface.
 *
 * A deny-list of exact strings is structurally unable to work: the next placeholder somebody
 * writes is, by definition, not on it. `@cloudsforge/secrets` asserts the SHAPE of a value
 * instead, which is the property a placeholder cannot have. It is imported rather than copied so
 * that this service cannot drift from the other sixteen.
 */

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * Re-wrap the shared guard's `SecretError` as this service's `EnvError`.
 *
 * `loadEnv` documents a single error class for every configuration failure, and the boot path
 * catches that one class. The message is preserved verbatim — it already names the variable and
 * the command that fixes it, and it never contains the value.
 */
function asEnvError<T>(run: () => T): T {
  try {
    return run()
  } catch (err) {
    if (err instanceof SecretError) throw new EnvError(err.message)
    throw err
  }
}

/**
 * The estate's shared event-bus HMAC key — here, the only thing between an unauthenticated POST
 * and a row written into the estate's audit of record naming any operator for any action.
 *
 * `assertGeneratedSecret` asserts what a placeholder cannot have: the base64 or hex alphabet (no
 * hyphens — every placeholder this estate wrote had one), 32 decoded BYTES rather than 24
 * keystrokes, and a measured Shannon entropy floor. The old `minLength` parameter is gone rather
 * than kept in front: it is a strict subset of the shape check, and running it first answers a
 * 40-character placeholder with "must be at least 24 characters" — true, useless, and about the
 * wrong property.
 */
function requiredSigningSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertGeneratedSecret(name, value))
  return value
}

/**
 * A SERVICE CREDENTIAL that may be absent, but must be REAL if present.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS REFUSES THE VALUE THE LIVE ESTATE IS RUNNING TODAY, AND THAT IS THE POINT — #222.**
 *
 * Measured live on 2026-08-05: `ADMIN_API_SERVICE_TOKEN` held a 701-byte JWT that had **expired 26
 * hours earlier**, on a container reporting healthy. It was genuinely read — `index.ts` closed over
 * `env.serviceToken` and `upstreams.ts` put it verbatim in the `authorization` header of every
 * ledger call a `{ kind: 'service' }` credential names, because `ledger/src/server.ts`'s
 * `authorise` refuses a user principal outright. So every reversal and every trial-balance read
 * this service made since that expiry answered 401, while `/livez` stayed green — the healthcheck
 * never exercises the credential, which is why nothing noticed for a day.
 *
 * A JWT read once at boot is dead ten minutes later, and dead on the next restart at the latest;
 * that is the ten-minute cliff (#197) wearing a variable name that looks fine.
 * `assertServiceCredential` refuses a JWT BY NAME, so a deployment still passing one will not
 * boot until it is replaced by a real `cfsc_` credential from `deploy/scripts/estate-bootstrap.sh`.
 * No JWT exemption and no weaker assertion.
 *
 * ── WHY `null` RATHER THAN `''`, AND WHY THE EMPTY CHECK COMES FIRST ───────────────────────────
 *
 * Compose interpolates `${ADMIN_API_IDENTITY_CREDENTIAL:-}`, so an UNSET credential arrives as the
 * EMPTY STRING rather than as `undefined`. That is the supported "not configured yet" mode, not a
 * malformed value, and `migrator.ts` shares this environment while dialling nobody — turning it
 * into `exit(1)` would fail `admin-api-migrate`, which the service's own compose block waits on
 * through `service_completed_successfully`. `null` says the absence once; `''` is falsy exactly
 * where a caller tests for it and truthy in `Object.keys`, which is how a mode gets chosen by
 * accident.
 *
 * What is NOT supported is a value that is present and rubbish. A 20-character placeholder is a
 * deployment that BELIEVES it has a credential, and it fails on its first ledger call with a 401
 * that reads exactly like the ledger being unwell.
 *
 * ── WHY NOT `assertGeneratedSecret` ────────────────────────────────────────────────────────────
 *
 * Because it would refuse every credential this estate has ever minted, on both networks. A
 * credential is `cfsc_` + base64url, which is neither wholly base64 nor wholly hex — the underscore
 * in its own prefix disqualifies it — and **the testnet body CONTAINS A HYPHEN while the mainnet
 * body does not**, so the "no hyphens" instinct that is correct for the signing key above reads as
 * obviously right, passes mainnet, and kills testnet at boot.
 */
function optionalCredential(source: Source, name: string): string | null {
  const value = source[name]?.trim()
  if (!value) return null
  asEnvError(() => assertServiceCredential(name, value))
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

/**
 * The secrets the inbound event route accepts, newest first.
 *
 * A LIST, not a value, because rotating `OUTBOX_SIGNING_SECRET` without an overlap window would
 * require every producer in the estate to change secret in the same instant this service does, and
 * that instant does not exist during a rolling deploy. A sender that moved first would simply be
 * refused, and what goes quiet here is the estate's audit of record — which during an incident
 * reads exactly like "nothing happened".
 *
 * Copied from `devplatform/src/env.ts`, which took the shape from activity's
 * `ACTIVITY_INGEST_SECRETS`. Each entry is validated exactly as a single secret is: a list is not a
 * way to smuggle in a value that `requiredSigningSecret` would refuse on its own.
 */
export function parseSecretList(raw: string, name: string): readonly string[] {
  // Argument order is flipped on the way through: this service's exported signature is
  // `(raw, name)` and the shared one is `(name, raw)`. Kept rather than changed because the
  // signature is part of this module's public surface, and a silent flip of two `string`
  // parameters is a change the type checker cannot catch.
  //
  // EVERY ENTRY FACES THE FULL RULE, INCLUDING THE OUTGOING ONE. In a rotation overlap window the
  // outgoing key is the one an attacker already holds if it leaked, and "just for the drain" is
  // exactly how a placeholder survives the rotation that was meant to remove it. The duplicate
  // check that used to live here moved with it, unchanged — a duplicated secret makes the "which
  // key verified this" answer ambiguous, and that answer is what tells an operator whether a
  // rotation has finished and the old key can be dropped.
  return asEnvError(() => parseSharedSecretList(name, raw))
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second one here fails the build rather than review.
   */
  readonly databaseUrl: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  /**
   * HMAC key for the event signatures this service EMITS. Exactly one, always: a producer signing
   * under two keys at once has not rotated, it has forked.
   */
  readonly outboxSigningSecret: string
  /**
   * The secrets `POST /v1/events` will ACCEPT, newest first.
   *
   * That route is how every other service mirrors its audit rows into this one (17 §2, SD-15), and
   * an unsigned inbound audit route is a forgery endpoint: anyone who could reach the port would be
   * able to write a row into the estate's audit of record naming any operator for any action. The
   * signature is checked over the exact bytes received, before `JSON.parse`.
   *
   * Defaults to `[outboxSigningSecret]` when `OUTBOX_ACCEPT_SECRETS` is unset, so a deploy that
   * does not set it behaves exactly as it does today. That is deliberate: it makes shipping this
   * change a no-op, which is what lets the rotation be staged one service at a time afterwards.
   */
  readonly acceptSecrets: readonly string[]
  readonly instanceId: string

  /** **Hard.** Every operator on this surface is authenticated against identity's JWKS. */
  readonly identityUrl: string
  /** Soft. Ledger reversals are an approval action; the trial-balance tile degrades without it. */
  readonly ledgerUrl: string
  /** Soft. Moderation resolution is an approval action; the open-cases tile degrades without it. */
  readonly marketUrl: string
  /** Soft. Entitlement revocation is an approval action. */
  readonly billingUrl: string
  /**
   * The long-lived, revocable `cfsc_` credential this process EXCHANGES for a service token.
   *
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * **THIS IS THE FIX, AND `serviceToken` BELOW IS THE THING IT REPLACES.**
   *
   * A credential is worth nothing on its own. `ServiceTokenProvider` posts it to identity's
   * `POST /service-tokens/exchange` (`identity/src/server.ts`) and gets back an ordinary
   * 600-second token (`identity/src/tokens.ts`), then re-mints before expiry on traffic. The
   * exchange consumes nothing, so N replicas boot from one credential and a restart six days later
   * still works. **The 600 seconds is deliberately unchanged**: rotation IS expiry, and a longer
   * TTL only moves the cliff — settlement's was 600 seconds and it still produced 1,315 undelivered
   * withdrawals, because the defect was never the number.
   *
   * `estate-bootstrap.sh` §5b already mints this into `tokens.env`; the deploy simply has to pass
   * it. Optional, because absence must be a boot the image survives — CI's startup smoke test and
   * `migrator.ts` both load this file, and neither dials a peer. `upstreams.ts` reports the mode it
   * chose and `index.ts` logs `fatal` when that mode cannot authenticate, which is the loud failure
   * the healthcheck could never be.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   */
  readonly identityCredential: string | null
  /**
   * The pre-minted service token. **A MIGRATION AID WITH A STATED END, NOT A MODE.**
   *
   * Held to `assertServiceCredential` exactly as `identityCredential` is, so the expired JWT the
   * estate is running today is refused BY NAME rather than presented for another day. It exists at
   * all only because `docker-compose.estate.yml` sets `ADMIN_API_SERVICE_TOKEN` and does not yet
   * pass `ADMIN_API_IDENTITY_CREDENTIAL`, and a deploy is not this repository's edit to make.
   * **Delete this field once the deploy passes the credential.**
   *
   * The variable's `*_SERVICE_TOKEN` name is worth saying out loud. Four variables in this estate
   * carry that suffix and they are not one class: measured on 2026-08-05, `SETTLEMENT_SERVICE_TOKEN`
   * held `cfsc_` + 43 characters while this one held a 701-byte expired JWT. **A guard chosen from
   * the NAME would have been right for exactly one of them**, which is why both are checked on the
   * shape of the value they actually carry.
   *
   * Whatever it holds, it loses to `identityCredential` when both are set — see `upstreams.ts`.
   * That precedence is the whole of the deploy's migration: add the credential, restart, remove
   * this one, and no window exists in which the dead token wins.
   */
  readonly serviceToken: string | null
  readonly upstreamDeadlineMs: number

  /**
   * How long an approval request may sit unanswered before the expiry job closes it.
   *
   * A queue whose entries never expire is a queue in which a request raised during one incident is
   * approved during the next, by somebody who was not in the room for either. Approval is consent
   * to an action in a context, and the context does not keep.
   */
  readonly approvalTtlMinutes: number
  /**
   * How much of the audit chain the verification job re-hashes on each pass.
   *
   * The chain is verified from the last known-good sequence forward, so this is a ceiling on one
   * pass rather than on the total. Zero would mean "never verify", which is why the floor is 1.
   */
  readonly auditVerifyBatch: number
  /** Retention for spent idempotency claims. Must outlive every caller's retry horizon. */
  readonly idempotencyTtlDays: number

  /**
   * Which estate this is — `mainnet`, `testnet` or `development`.
   *
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * **REQUIRED, WITH NO DEFAULT, AND THE ABSENCE OF A DEFAULT IS THE WHOLE CONTROL.**
   *
   * A default here would be a default answer to "which estate am I?", and the wrong answer to that
   * question restores a testnet backup over real balances. On 2026-08-05 the estate seeder took a
   * target parameter and ran against the MAINNET project regardless, twice — so the failure mode is
   * measured, not imagined.
   *
   * At boot this value is compared against `estate_identity`, a row claimed once and immutable
   * thereafter. A disagreement is a REFUSAL TO START: it means either this container is pointed at
   * the wrong database or the compose file is labelled wrongly, and both are things that must be
   * discovered by a container that will not boot rather than by a restore six weeks later.
   *
   * The variable carries no credential vocabulary in its name, so `secret-hygiene` has nothing to
   * say about it — the same reason the durations here are `…_MINUTES` and `…_DAYS`.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   */
  readonly estateEnvironment: 'mainnet' | 'testnet' | 'development'
  /**
   * The compose project this estate runs under — `cloudsforge-estate` or `cf-testnet`.
   *
   * Recorded on every backup run because it is what names the docker volumes a restore has to put
   * back (`<project>_custody-keys`). It is descriptive rather than enforcing: the ENVIRONMENT is
   * what a restore is gated on, and this is what tells an operator which volumes the set came from.
   */
  readonly composeProject: string
}

const ESTATE_ENVIRONMENTS = new Set(['mainnet', 'testnet', 'development'])

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  // `required`, not `optional`. See the field's comment: a default answer to "which estate am I?"
  // is how a testnet backup gets restored over mainnet balances.
  const estateEnvironment = required(source, 'ADMIN_API_ESTATE_ENVIRONMENT')
  if (!ESTATE_ENVIRONMENTS.has(estateEnvironment)) {
    throw new EnvError(
      `ADMIN_API_ESTATE_ENVIRONMENT must be one of mainnet, testnet, development (got ${estateEnvironment})`,
    )
  }

  // Read before the object literal because the accept list falls back to it.
  const outboxSigningSecret = requiredSigningSecret(source, 'OUTBOX_SIGNING_SECRET')

  return {
    port: integer(source, 'PORT', 4014, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'ADMIN_API_DATABASE_URL'),
    databasePoolMax: integer(source, 'ADMIN_API_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    outboxSigningSecret,
    acceptSecrets: parseSecretList(
      optional(source, 'OUTBOX_ACCEPT_SECRETS', outboxSigningSecret),
      'OUTBOX_ACCEPT_SECRETS',
    ),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),

    identityUrl: required(source, 'IDENTITY_URL'),
    ledgerUrl: required(source, 'LEDGER_URL'),
    marketUrl: required(source, 'MARKET_URL'),
    billingUrl: required(source, 'BILLING_URL'),
    // The credential that is EXCHANGED, and the token that is not. Both face the same assertion,
    // because the class of a value is a property of the value and never of the variable holding
    // it: the live `ADMIN_API_SERVICE_TOKEN` is an expired JWT and this refuses it, which is #222
    // being closed rather than a regression.
    identityCredential: optionalCredential(source, 'ADMIN_API_IDENTITY_CREDENTIAL'),
    serviceToken: optionalCredential(source, 'ADMIN_API_SERVICE_TOKEN'),
    upstreamDeadlineMs: integer(source, 'ADMIN_API_UPSTREAM_DEADLINE_MS', 5_000, 100, 60_000),

    // Default four hours. Long enough that a second operator in another timezone can answer,
    // short enough that a request does not survive the incident that produced it.
    approvalTtlMinutes: integer(source, 'ADMIN_API_APPROVAL_TTL_MINUTES', 240, 1, 20_160),
    auditVerifyBatch: integer(source, 'ADMIN_API_AUDIT_VERIFY_BATCH', 5_000, 1, 1_000_000),
    idempotencyTtlDays: integer(source, 'ADMIN_API_IDEMPOTENCY_TTL_DAYS', 14, 1, 365),

    estateEnvironment: estateEnvironment as Env['estateEnvironment'],
    // Defaulted, unlike the environment, and the asymmetry is deliberate: the compose default IS
    // `cloudsforge-estate` (see deploy/compose/mainnet.env, which omits CF_PROJECT for exactly that
    // reason), and this value is descriptive rather than a gate. Getting it wrong names the wrong
    // volumes in a manifest; getting the environment wrong destroys balances.
    composeProject: optional(source, 'ADMIN_API_COMPOSE_PROJECT', 'cloudsforge-estate'),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed through
 * the telemetry package: nothing that can itself fail may sit between a configuration error and
 * the report of it.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
