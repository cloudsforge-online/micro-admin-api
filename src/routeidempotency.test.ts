/**
 * Every mutating route either replays a retry or has a documented reason not to.
 *
 * WHY THIS IS A SOURCE-LEVEL TEST. Copied from `market/src/routeidempotency.test.ts`, which market
 * gained after `POST /v1/orders/:id/disputes` and `POST /v1/moderation/cases` were both found with
 * no wrapper — a double-clicked button opened two disputes on one order and froze the listing
 * twice. Both sat beside four sibling routes that wrap correctly, and nothing noticed, because the
 * domain tests call the functions directly and never traverse the route.
 *
 * So this asserts the *shape of the file* rather than behaviour, deliberately: the defect is an
 * OMISSION, and an omission has no behaviour to test. A route added tomorrow without a wrapper
 * fails here, and the author must either wrap it or write down why it does not need one.
 *
 * The stakes on this surface are the reason it is copied rather than skipped: a duplicated
 * approval request is two identical pending reversals, approved by two different second operators,
 * and the ledger's own idempotency would not catch the second — the executor derives its key from
 * the approval id, and two approvals have two ids.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { ACTIONS, BLOCKED_ACTIONS, EXECUTABLE_ACTIONS, EXECUTORS } from './actions.ts'

const SERVER = readFileSync(fileURLToPath(new URL('./server.ts', import.meta.url)), 'utf8')

/**
 * Mutating routes that are safe WITHOUT the wrapper, each with the reason it is safe. A route is
 * only exempt if retrying it a second time cannot produce a second artefact.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  'POST /v1/events':
    'the audit mirror inbox, deduplicated on (topic, event_id) AND on audit_events.source_event_id — its idempotency is the whole point of both',
  'PUT /v1/flags/:key':
    'an upsert keyed on the flag key. A retry writes the same row; the audit records what the value was before, so a replayed no-op is visible as one rather than as a second change',
  'DELETE /v1/broadcasts/:id':
    'a state transition claimed with `where retracted_at is null`; the second attempt matches no row and is refused rather than audited twice',
}

function mutatingRoutes(): Array<{ key: string; wrapped: boolean }> {
  const out: Array<{ key: string; wrapped: boolean }> = []
  const re = /define\('(POST|PUT|PATCH|DELETE)', '([^']+)'/g
  const starts: Array<{ key: string; at: number }> = []
  for (let m = re.exec(SERVER); m !== null; m = re.exec(SERVER)) {
    starts.push({ key: `${m[1]} ${m[2]}`, at: m.index })
  }
  const all = [...SERVER.matchAll(/define\('[A-Z]+', '[^']+'/g)].map((m) => m.index ?? 0)
  for (const s of starts) {
    const next = all.find((i) => i > s.at) ?? SERVER.length
    out.push({ key: s.key, wrapped: SERVER.slice(s.at, next).includes('withIdempotentRoute') })
  }
  return out
}

test('every mutating route replays a retry, or says why it need not', () => {
  const unexplained = mutatingRoutes()
    .filter((r) => !r.wrapped && !(r.key in EXEMPT))
    .map((r) => r.key)
  assert.deepEqual(
    unexplained,
    [],
    `these mutating routes neither wrap withIdempotentRoute nor appear in EXEMPT:\n  ${unexplained.join('\n  ')}\n` +
      'A retried request must not create a second artefact. Wrap it, or add it to EXEMPT with the reason it is safe.',
  )
})

test('the two routes that create durable artefacts are wrapped', () => {
  const byKey = new Map(mutatingRoutes().map((r) => [r.key, r.wrapped]))
  assert.equal(byKey.get('POST /v1/approvals'), true, 'a retry must not raise a second request')
  assert.equal(byKey.get('POST /v1/broadcasts'), true, 'a retry must not publish a second notice')
  // And the decision route, which is the one that CALLS AN UPSTREAM. A retry there without the
  // wrapper is a second reversal against the ledger.
  assert.equal(byKey.get('POST /v1/approvals/:id/decision'), true, 'a retry must not execute twice')
})

test('the checker sees the routes at all', () => {
  // An empty list passes the first test vacuously. This is the line that stops that.
  const routes = mutatingRoutes()
  assert.ok(routes.length >= 5, `expected several mutating routes, found ${routes.length}`)
  assert.ok(routes.some((r) => r.wrapped), 'no route was detected as wrapped — the detector is broken')
})

test('no exemption is stale', () => {
  // An exemption for a route that no longer exists is a claim nobody is checking, and it hides the
  // day that route comes back without a wrapper.
  const keys = new Set(mutatingRoutes().map((r) => r.key))
  for (const k of Object.keys(EXEMPT)) {
    assert.ok(keys.has(k), `EXEMPT names ${k}, which is not a route on this server any more`)
  }
})

/* ------------------------------------------------------------------ the action catalogue */

test('every executable action has an executor, and every blocked one does not', () => {
  // The catalogue is data so this can be checked. An action added with a route and no executor
  // would 501 at execution time — after two operators had already signed for it.
  for (const name of EXECUTABLE_ACTIONS) {
    assert.ok(EXECUTORS[name], `${name} names a route but has no executor`)
  }
  for (const name of BLOCKED_ACTIONS) {
    assert.equal(EXECUTORS[name], undefined, `${name} has no route but has an executor`)
  }
})

test('a blocked action states WHY, and the reason names what is missing', () => {
  for (const name of BLOCKED_ACTIONS) {
    const spec = ACTIONS[name]!
    assert.ok(spec.blockedReason, `${name} is blocked with no reason recorded`)
    assert.ok(spec.blockedReason.length > 80, `${name}'s reason is too short to be useful to whoever unblocks it`)
  }
})

test('every executable action cites the route it calls, by path and line', () => {
  // Six times in this estate a client was built against an imagined surface. A citation is what
  // makes the next one checkable.
  for (const name of EXECUTABLE_ACTIONS) {
    const route = ACTIONS[name]!.route!
    assert.match(route, /^(GET|POST|PUT|DELETE) \//, `${name}'s route citation does not start with a method and a path`)
    assert.match(route, /\.ts:\d+/, `${name} does not cite a path:line in the provider's source`)
  }
})

test('the blocked list is exactly the role grant — the §3.3g answer', () => {
  assert.deepEqual([...BLOCKED_ACTIONS], ['identity.role.grant'])
})

test('every action names a subject kind, and none of them is a user costume', () => {
  for (const [name, spec] of Object.entries(ACTIONS)) {
    assert.ok(spec.subjectKind.length > 0, `${name} names no subject kind`)
    assert.ok(spec.requiredParams.length > 0, `${name} requires no parameters, which is unlikely to be right`)
  }
  // The one action whose subject IS a user is the blocked one, and it is a SUBJECT — the thing
  // acted upon — never an identity the operator borrows.
  assert.equal(ACTIONS['identity.role.grant']!.subjectKind, 'user')
})
