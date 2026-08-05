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
 *   2. **A known placeholder is refused outright.** A default secret in source is not convenient,
 *      it is catastrophic, and a placeholder that boots is a placeholder that reaches production.
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

const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'change_me',
  'placeholder',
  'secret',
  'token',
  'dev-secret',
  'dev-outbox-signing-secret',
  'replace-with-a-real-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

function requiredSecret(source: Source, name: string, minLength = 24): string {
  const value = required(source, name)
  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  // Length is a proxy for entropy and the only one available here. It is set above the point at
  // which a human-chosen string is plausible, so a memorable password fails this check too.
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
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
 * Copied from `devplatform/src/env.ts:103`, which took the shape from activity's
 * `ACTIVITY_INGEST_SECRETS`. Each entry is validated exactly as a single secret is: a list is not a
 * way to smuggle in a value that `requiredSecret` would refuse on its own.
 */
export function parseSecretList(raw: string, name: string): readonly string[] {
  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  if (entries.length === 0) throw new EnvError(`${name} is required — at least one secret`)
  for (const entry of entries) {
    if (PLACEHOLDERS.has(entry.toLowerCase())) {
      throw new EnvError(`${name} contains a known placeholder — generate real secrets`)
    }
    if (entry.length < 24) {
      throw new EnvError(`${name} entries must each be at least 24 characters`)
    }
  }
  if (new Set(entries).size !== entries.length) {
    // A duplicated secret makes the "which key verified this" answer ambiguous, and that answer is
    // what tells an operator whether a rotation has finished and the old key can be dropped.
    throw new EnvError(`${name} lists the same secret twice`)
  }
  return Object.freeze(entries)
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
  /** The scoped service credential. Not shared: SD-05. */
  readonly serviceToken: string
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
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  // Read before the object literal because the accept list falls back to it.
  const outboxSigningSecret = requiredSecret(source, 'OUTBOX_SIGNING_SECRET')

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
    serviceToken: requiredSecret(source, 'ADMIN_API_SERVICE_TOKEN'),
    upstreamDeadlineMs: integer(source, 'ADMIN_API_UPSTREAM_DEADLINE_MS', 5_000, 100, 60_000),

    // Default four hours. Long enough that a second operator in another timezone can answer,
    // short enough that a request does not survive the incident that produced it.
    approvalTtlMinutes: integer(source, 'ADMIN_API_APPROVAL_TTL_MINUTES', 240, 1, 20_160),
    auditVerifyBatch: integer(source, 'ADMIN_API_AUDIT_VERIFY_BATCH', 5_000, 1, 1_000_000),
    idempotencyTtlDays: integer(source, 'ADMIN_API_IDEMPOTENCY_TTL_DAYS', 14, 1, 365),
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
