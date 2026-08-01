/**
 * Run a mutating operation at most once per key.
 *
 * **The shape is market's** (`market/src/idempotency.ts`), which is the ledger's, which took it
 * from `repos/forge-pay/services/pay/src/store.ts:153`. It is not reinvented here; it is
 * inherited, because the four properties below are the whole of the correctness and each is easy
 * to lose while writing something that looks equivalent:
 *
 *   1. **The claim INSERT and the work share ONE transaction.** The stored response can therefore
 *      never disagree with what actually committed.
 *   2. **A concurrent duplicate blocks rather than races.** The second INSERT waits on the first
 *      transaction's uncommitted row; when that commits, the duplicate reads the stored response
 *      and replays it.
 *   3. **A reused key with a different body is refused, not replayed.** Returning the first
 *      request's answer to a second, different request is worse than an error: the caller believes
 *      the thing it asked for happened.
 *   4. **A claim with no response yet is "in flight", not "done".**
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THIS MATTERS ON AN OPERATOR SURFACE, WHICH IS NOT OBVIOUS.**
 *
 * The usual argument is a double-clicked Buy button. Here the artefact is an approval request, and
 * a duplicate one is worse than a duplicate order: two identical pending requests for the same
 * ledger reversal, approved by two different second operators, execute the reversal twice. The
 * ledger's own idempotency would catch the second — `EXECUTORS['ledger.entry.reverse']` derives
 * its key from the approval id, and the two approvals have different ids, so it would NOT. This
 * wrapper is what stops the second request existing at all.
 *
 * `correlationId`, `idempotencyKey` and `requestId` are excluded from the fingerprint. A trace id
 * is SUPPOSED to change on every attempt — the ledger fingerprinted the whole body including it,
 * and so every honest retry would have 409'd in production. That regression is documented in
 * `ledger/src/idempotency.test.ts` and pinned here in both directions.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { createHash } from 'node:crypto'
import type { Db, Tx } from './outbox.ts'

/** The claim exists but its transaction has not committed a response yet. The caller retries. */
export class IdempotencyInFlightError extends Error {
  constructor() {
    super('a request with this idempotency key is still in flight; retry shortly')
    this.name = 'IdempotencyInFlightError'
  }
}

/** The same key was presented with a different body. 409, always. */
export class IdempotencyKeyReuseError extends Error {
  constructor() {
    super('this idempotency key was already used with a different request body')
    this.name = 'IdempotencyKeyReuseError'
  }
}

/** Fields that legitimately differ between attempts at the *same* operation. See the header. */
const PER_ATTEMPT_FIELDS = new Set(['correlationId', 'idempotencyKey', 'requestId'])

/**
 * A stable fingerprint of a request body, so a reused key with a changed payload is caught.
 *
 * Keys are sorted at every depth before hashing. `JSON.stringify` preserves insertion order, so
 * two semantically identical bodies that serialised their fields in a different order would
 * fingerprint differently and a legitimate retry would be rejected as reuse.
 */
export function requestFingerprint(value: unknown): string {
  const subject =
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(
          Object.entries(value as Record<string, unknown>).filter(
            ([key]) => !PER_ATTEMPT_FIELDS.has(key),
          ),
        )
      : value
  return createHash('sha256').update(canonicalise(subject)).digest('hex')
}

function canonicalise(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'bigint') return `"${value.toString()}"`
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalise).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalise(v)}`).join(',')}}`
}

/**
 * The stored key, namespaced by the calling principal and the route.
 *
 * **The principal, not the service.** Two operators independently choosing `remediate-2026-08-01`
 * must not collide — and on this surface a collision would mean one operator's approval request
 * replaying as the answer to another's, which would show the wrong name in the audit. Elsewhere in
 * the estate this namespace is the calling service; here a service is not what acts.
 */
export function namespacedKey(principal: string, route: string, clientKey: string): string {
  return `${principal}:${route}:${clientKey}`
}

export interface IdempotentOutcome<T> {
  readonly result: T
  readonly replayed: boolean
}

export interface IdempotencyInput<T> {
  readonly principal: string
  readonly route: string
  readonly clientKey: string
  readonly requestHash: string
  readonly run: (tx: Tx, storedKey: string) => Promise<{ response: T; artefactId: string | null }>
}

export async function withIdempotency<T>(
  sql: Db,
  input: IdempotencyInput<T>,
): Promise<IdempotentOutcome<T>> {
  const key = namespacedKey(input.principal, input.route, input.clientKey)

  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ key: string }[]>`
      insert into idempotency_keys (key, route, request_hash)
      values (${key}, ${input.route}, ${input.requestHash})
      on conflict (key) do nothing
      returning key
    `

    if (claimed.length === 0) {
      // Someone else holds the key. By the time this read runs, their transaction has either
      // committed (so the response is here) or rolled back (so the row is gone).
      const rows = await tx<{ request_hash: string; response: unknown }[]>`
        select request_hash, response from idempotency_keys where key = ${key}
      `
      const existing = rows[0]
      if (!existing) throw new IdempotencyInFlightError()
      if (existing.request_hash !== input.requestHash) throw new IdempotencyKeyReuseError()
      if (existing.response === null || existing.response === undefined) {
        throw new IdempotencyInFlightError()
      }
      return { value: { result: existing.response as T, replayed: true } }
    }

    const { response, artefactId } = await input.run(tx, key)

    await tx`
      update idempotency_keys
         set response = ${tx.json(response as Record<string, never>)},
             artefact_id = ${artefactId}
       where key = ${key}
    `

    return { value: { result: response, replayed: false } }
  })

  // Wrapped in an object above so postgres.js does not treat an array-shaped result as a list of
  // promises to unwrap, which would rewrite the caller's return type.
  return outcome.value
}

/**
 * How many keys one DELETE claims.
 *
 * An unbounded DELETE over a table that has never been pruned is a single long transaction holding
 * a row lock on everything it removes. Short statements let autovacuum keep up.
 */
const REAP_BATCH = 5_000

/**
 * Delete idempotency keys past their TTL. Returns how many rows went.
 *
 * A claim row that produced an artefact is kept regardless of age. It is the only link between an
 * operator's key and the approval it raised, and losing it turns "did my retry raise this twice"
 * into an unanswerable question.
 */
export async function reapIdempotencyKeys(sql: Db, ttlDays: number): Promise<number> {
  // An ISO string with an explicit cast, not a Date: postgres.js resolves a prepared statement's
  // parameter types from the server's ParameterDescription, and inside a subquery it does not come
  // back with the timestamptz serialiser — a raw Date is then handed to the text encoder and
  // throws.
  const cutoff = new Date(Date.now() - ttlDays * 24 * 60 * 60 * 1000).toISOString()
  let total = 0
  for (;;) {
    const result = await sql`
      delete from idempotency_keys
       where key in (
         select key from idempotency_keys
          where created_at < ${cutoff}::timestamptz
            and artefact_id is null
          limit ${REAP_BATCH}
       )
    `
    total += result.count
    if (result.count < REAP_BATCH) return total
  }
}
