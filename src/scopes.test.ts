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
import { ALL_SCOPES, MIRROR_SCOPE, READ_SCOPE, hasExactScope, requireExactScope } from './scopes.ts'
import { operatorPrincipal, servicePrincipal, ALICE } from './testsupport.ts'

test('an exact scope is granted', () => {
  const principal = servicePrincipal('lantern', [READ_SCOPE])
  assert.equal(hasExactScope(principal, READ_SCOPE), true)
  assert.doesNotThrow(() => requireExactScope(principal, READ_SCOPE))
})

test('a scope not held is refused, and names what was required', () => {
  const principal = servicePrincipal('lantern', [READ_SCOPE])
  assert.equal(hasExactScope(principal, MIRROR_SCOPE), false)
  assert.throws(
    () => requireExactScope(principal, MIRROR_SCOPE),
    (err: unknown) => {
      assert.ok(err instanceof ForbiddenError)
      assert.equal(err.required, MIRROR_SCOPE)
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
  // Not a hypothetical. `runtime/packages/auth/src/index.ts:178` honours one wildcard level, and
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

test('the vocabulary is exactly two scopes, and neither can act', () => {
  // There is no `admin:execute`. Every action that changes another service travels through the
  // approval queue, and an approval names two HUMAN operators.
  assert.deepEqual([...ALL_SCOPES].sort(), ['admin:audit:write', 'admin:read'])
})

test('`admin:audit:write` does not imply `admin:read` under the exact reading', () => {
  // It would under a prefix reading, since one is a prefix of nothing here — but a mirroring
  // service should be able to WRITE its own audit rows without being able to READ the estate's.
  const mirror = servicePrincipal('ledger', [MIRROR_SCOPE])
  assert.equal(hasExactScope(mirror, READ_SCOPE), false)
  assert.equal(hasExactScope(mirror, MIRROR_SCOPE), true)
})
