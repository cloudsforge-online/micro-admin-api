/**
 * The scope matcher, and the §3.3h decision pinned in both directions.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * 18-build-status.md §3.3h records that the estate ships two matchers that disagree, and
 * concludes they are "left as it is, deliberately" because changing an authorisation matcher is
 * the highest-blast-radius edit available here. **Neither package is modified by this
 * repository.** What this file does is prove which reading THIS service uses, and prove that the
 * difference is real rather than theoretical — so nobody has to rediscover it from a 403.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ForbiddenError, hasScope } from '@cloudsforge/auth'
import { ALL_SCOPES, READ_SCOPE, hasExactScope, requireExactScope } from './scopes.ts'
import { operatorPrincipal, servicePrincipal, ALICE } from './testsupport.ts'

/**
 * A scope this service does NOT define, used to prove refusal.
 *
 * Deliberately a literal rather than a second real scope: the vocabulary is one scope now, and a
 * refusal test that borrows another live scope stops working the moment the vocabulary changes —
 * which is exactly what just happened to `admin:audit:write`.
 */
const NOT_A_SCOPE = 'admin:audit:write'

test('an exact scope is granted', () => {
  const principal = servicePrincipal('lantern', [READ_SCOPE])
  assert.equal(hasExactScope(principal, READ_SCOPE), true)
  assert.doesNotThrow(() => requireExactScope(principal, READ_SCOPE))
})

test('a scope not held is refused, and names what was required', () => {
  const principal = servicePrincipal('lantern', [READ_SCOPE])
  assert.equal(hasExactScope(principal, NOT_A_SCOPE), false)
  assert.throws(
    () => requireExactScope(principal, NOT_A_SCOPE),
    (err: unknown) => {
      assert.ok(err instanceof ForbiddenError)
      assert.equal(err.required, NOT_A_SCOPE)
      return true
    },
  )
})

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE DECISION.
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('THE §3.3h CHOICE: `admin:*` is REFUSED on this service', () => {
  const wildcard = servicePrincipal('some-service', ['admin:*'])
  for (const scope of ALL_SCOPES) {
    assert.equal(
      hasExactScope(wildcard, scope),
      false,
      `admin:* must not grant ${scope} — that is one string granting the whole operator surface`,
    )
  }
})

test('and the difference is REAL: runtime\'s hasScope would have granted it', () => {
  // Not a hypothetical. `runtime/packages/auth/src/index.ts` honours one wildcard level, and
  // that is the package this service imports. Calling `hasScope` here instead of `hasExactScope`
  // would hand `admin:*` the audit mirror and the approval queue.
  const wildcard = servicePrincipal('some-service', ['admin:*'])
  assert.equal(hasScope(wildcard, READ_SCOPE), true, 'runtime grants it — this is the disagreement §3.3h records')
  assert.equal(hasExactScope(wildcard, READ_SCOPE), false, 'this service does not')
})

test('a bare `*` grants nothing under either reading', () => {
  // runtime is explicit that a bare `*` is not a scope, "because a credential that grants
  // everything is a credential nobody can reason about". Both agree here; the disagreement is
  // only about the prefixed form.
  const star = servicePrincipal('some-service', ['*'])
  assert.equal(hasExactScope(star, READ_SCOPE), false)
  assert.equal(hasScope(star, READ_SCOPE), false)
})

test('a prefix that is not a wildcard grants nothing', () => {
  const prefix = servicePrincipal('some-service', ['admin'])
  assert.equal(hasExactScope(prefix, READ_SCOPE), false)
})

test('a user principal holds no scopes at all', () => {
  // An operator's authority comes from `role:admin`, never from a scope. Two vocabularies that
  // could both grant the same route is how an authorisation model becomes unauditable.
  const operator = operatorPrincipal(ALICE)
  assert.equal(hasExactScope(operator, READ_SCOPE), false)
  assert.equal(hasScope(operator, READ_SCOPE), false)
})

test('THE VOCABULARY IS EXACTLY ONE SCOPE, and it cannot act', () => {
  // There is no `admin:execute`. Every action that changes another service travels through the
  // approval queue, and an approval names two HUMAN operators.
  //
  // And there is no `admin:audit:write` any more: it gated the audit mirror, no outbox relay in
  // the estate can present a bearer at all, so the mirror received nothing while the vocabulary
  // advertised a capability that was exercised zero times. `server.ts` carries the argument.
  assert.deepEqual([...ALL_SCOPES].sort(), ['admin:read'])
})

test('A SCOPE THIS SERVICE NO LONGER DEFINES GRANTS NOTHING, even to a service that holds it', () => {
  // The point of deleting a constant rather than leaving it unreferenced: a token minted with the
  // retired scope must not quietly keep working. It buys nothing, including on the mirror.
  const holder = servicePrincipal('ledger', [NOT_A_SCOPE])
  assert.equal(hasExactScope(holder, READ_SCOPE), false)
  assert.equal(ALL_SCOPES.includes(NOT_A_SCOPE), false)
})
