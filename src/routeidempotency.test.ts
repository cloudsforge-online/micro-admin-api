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
import { ACTIONS, BLOCKED_ACTIONS, EXECUTABLE_ACTIONS, EXECUTORS, READ_ACTIONS } from './actions.ts'

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
  'PUT /v1/engagement/policies/:service':
    'an upsert keyed on the service, exactly like PUT /v1/flags/:key: a retry writes the same row, the audit payload carries before and after, and the lowering it performs is idempotent by value — the raise path travels through POST /v1/approvals, which IS wrapped',
  'PUT /v1/backups/settings':
    'an UPDATE of one singleton row whose every column is last-write-wins. A retry writes the same eight values and produces no second artefact — no backup is taken, no restore is queued, nothing is created. The two routes here that DO create durable artefacts, POST /v1/backups and POST /v1/restores, are both wrapped',
  'POST /v1/worlds':
    "the world is nda's artefact, not this service's, and the key that guards it is the caller's own: the route REFUSES the request with a 400 when no Idempotency-Key header is present rather than inventing one, forwards it verbatim, and nda's `idempotently` replays the first world it built under that key — a retry answers 200 with replayed:true instead of 201, and generates no second map. Wrapping here would answer the retry out of this service's store and never ask nda, which is how the two records drift: this one would keep replaying a 201 for a world nda had since refused or archived",
  'POST /v1/worlds/:id/start':
    'a lobby→active transition claimed by nda under the forwarded key, which this route demands rather than defaults. A retry re-reads the same world and the audit payload records replayed, so a replayed no-op is visible as one — the same standard PUT /v1/flags/:key is held to',
  'POST /v1/worlds/:id/tick':
    "enqueues one day behind the world's lease. The lease is the real guard — the scheduler's sweep and an operator's force-tick cannot both advance the same day, whatever the key says — and the forwarded Idempotency-Key makes the retry itself a replay on top of that. A second 202 does not resolve a second day",
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
  // And a READ has no executor either: the queue refuses it at creation, so an executor for one
  // would be dead code waiting for a route change to make it reachable.
  for (const name of READ_ACTIONS) {
    assert.equal(EXECUTORS[name], undefined, `${name} is a read but has an executor`)
  }
})

test('a read action is refused by the queue and served by a GET it names', () => {
  // 21 §6: engagement.report's approval column is "none (read)". The catalogue carries it so the
  // console renders all three engagement actions; the queue refuses it; and its route citation
  // must name the GET an operator calls instead.
  assert.deepEqual([...READ_ACTIONS], ['engagement.report'])
  for (const name of READ_ACTIONS) {
    const spec = ACTIONS[name]!
    assert.equal(spec.approval, 'read')
    assert.match(spec.route ?? '', /^GET \//, `${name}'s route must name the GET that serves it`)
    assert.ok(
      SERVER.includes(`'${(spec.route ?? '').split(' — ')[0]!.replace(/^GET /, '')}'`),
      `${name}'s GET route is not defined on this server`,
    )
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
  // Clients in this estate have repeatedly been built against imagined surfaces — 18-build-status
  // §3.3i and §3.3m. A citation is what makes the next one checkable.
  for (const name of EXECUTABLE_ACTIONS) {
    const route = ACTIONS[name]!.route!
    assert.match(route, /^(GET|POST|PUT|DELETE) \//, `${name}'s route citation does not start with a method and a path`)
    assert.match(route, /\.ts:\d+/, `${name} does not cite a path:line in the provider's source`)
  }
})

/**
 * **THE BLOCKED LIST IS NOW EMPTY, AND THAT IS AN INTENTIONAL EXPECTATION CHANGE.**
 *
 * This asserted `['identity.role.grant']` — the §3.3g answer — and it was written to fail on the
 * day identity grew the route this repository's `actions.ts` header specified. That day is today:
 * `micro-identity` has landed `PUT /internal/users/:id/roles`, gated on a SERVICE token holding
 * `identity:admin`, writing a `platform_role_grants` row with `source='approval'` in the same
 * transaction as the `users.roles` update, behind a deferred trigger that refuses the update
 * without it. So the action has an upstream, an executor and a route citation.
 *
 * **This is not a weakening of the §3.3g answer; it is that answer being completed.** §3.3g said
 * the WRITE belongs to identity and the AUTHORISATION belongs here. Both are now true. What has
 * NOT changed, and what the assertions below pin, is that this service is not the escalation
 * route: reaching the executor needs an approval two DISTINCT operators signed, which needs an
 * administrator to already exist, and the FIRST one still comes from identity's one-shot
 * deploy-time bootstrap. `bootstrap.test.ts` holds that line.
 */
test('NOTHING IS BLOCKED ANY MORE, and the role grant is what changed', () => {
  assert.deepEqual([...BLOCKED_ACTIONS], [])
  const spec = ACTIONS['identity.role.grant']!
  assert.equal(spec.upstream, 'identity')
  assert.equal(spec.blockedReason, null)
  assert.ok(spec.route, 'an executable action with no route citation is the defect §3.3i records')
  // Still two-operator. An action becoming executable must not also become cheaper to authorise.
  assert.equal(spec.approval, 'two-operator')
})

test('every action names a subject kind, and none of them is a user costume', () => {
  for (const [name, spec] of Object.entries(ACTIONS)) {
    assert.ok(spec.subjectKind.length > 0, `${name} names no subject kind`)
    // A two-operator action with no parameters is a mutation described by nothing but its
    // subject id, which is almost always a decision someone forgot to require. A READ takes its
    // parameters as query strings on the GET it names, so the rule does not apply to it.
    if (spec.approval === 'two-operator') {
      assert.ok(spec.requiredParams.length > 0, `${name} requires no parameters, which is unlikely to be right`)
    }
  }
  // The actions whose subject IS a user, as a CLOSED set. This comment used to say "the one
  // action whose subject IS a user is the blocked one" and was wrong twice over by the time
  // micro-org#317 read it — the grant stopped being blocked when identity built the route, and it
  // is no longer alone. Pinned as a set rather than as one equality because `subject_kind = 'user'`
  // is now load-bearing: `approvals_decider_is_not_the_subject` and `principalForSubject` are both
  // scoped to it, so an action that started naming a person without appearing here would be an
  // action outside the beneficiary check with nothing to say so.
  const userSubjects = Object.entries(ACTIONS)
    .filter(([, spec]) => spec.subjectKind === 'user')
    .map(([name]) => name)
    .sort()
  assert.deepEqual(userSubjects, ['identity.role.grant', 'identity.role.revoke'])
  // And in every case it is a SUBJECT — the thing acted upon — never an identity the operator
  // borrows. `server.test.ts` asserts no route reads a user id from the request at all.
})

test('the engagement catalogue is exactly 21 §6, with the schema behind each promise', () => {
  // The three actions the document's table names, in the catalogue's shape. Pinned as a closed
  // set the way BLOCKED_ACTIONS is: an engagement action added or renamed without this test
  // changing is an action nobody decided.
  const engagement = Object.keys(ACTIONS).filter((name) => name.startsWith('engagement.'))
  assert.deepEqual(engagement.sort(), ['engagement.policy.set', 'engagement.report', 'engagement.transfer'])
  assert.equal(ACTIONS['engagement.transfer']!.approval, 'two-operator')
  assert.equal(ACTIONS['engagement.policy.set']!.approval, 'two-operator')
  assert.equal(ACTIONS['engagement.report']!.approval, 'read')
  // The transfer's summary must say where the cap binds, because that is the claim 21 §7.3
  // audits: the schema, not the route.
  assert.match(ACTIONS['engagement.transfer']!.summary, /schema/i)
  // And the policy action must name the asymmetry, so the console shows an operator WHY their
  // lower went through without the queue.
  assert.match(ACTIONS['engagement.policy.set']!.summary, /lower/i)
})
