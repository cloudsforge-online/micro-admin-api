/**
 * This service's scope vocabulary, and the matcher it uses.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE §3.3h DECISION: EXACT MATCH ONLY, ON THIS SERVICE, DELIBERATELY.**
 *
 * 18-build-status.md §3.3h records that the estate ships two scope matchers that disagree:
 *
 *   | `contracts/packages/auth` | `src/index.ts:209` | `granted.includes(required)` — exact only |
 *   | `runtime/packages/auth`   | `src/index.ts:178` | one wildcard level: `foo:*` grants `foo:bar` |
 *
 * Both are shipped, both are CI-green, and neither is wrong on its own terms. **Neither is changed
 * by this repository**, per §3.3h's conclusion that changing an authorisation matcher is the
 * highest-blast-radius edit available in this estate and wants the owner rather than an agent.
 *
 * This service imports `@cloudsforge/auth` from **runtime** — as every service here does — and
 * then deliberately does NOT call its `hasScope`. `requireAdminScope` below uses `includes`,
 * which is the contracts-package reading. Three reasons, in increasing order of weight:
 *
 *   1. **The blast radius is asymmetric.** Over-granting on the operator surface hands somebody
 *      the estate. Under-granting hands somebody a 403 they can get fixed in a morning. When two
 *      readings are both defensible, the one whose failure is recoverable wins.
 *
 *   2. **`admin:*` is exactly the credential this estate exists to remove.** The wildcard form is
 *      documented and deliberate in runtime — a *bare* `*` still grants nothing — but `admin:*`
 *      is one string that grants approving a ledger reversal, flipping a feature flag, publishing
 *      a broadcast and reading the estate's audit of record. That is `PAY_SERVICE_TOKEN` with a
 *      new spelling (SD-05, SD-12).
 *
 *   3. **`micro-devplatform` already navigated it this way**, using `includes` rather than
 *      `hasScope` on `/internal/keys/verify` with a test proving `devplatform:*` is refused. A
 *      credential service and an operator surface should not be the two places the estate
 *      discovers its wildcard semantics differ, and consistency between them is worth more than
 *      either answer.
 *
 * The cost is stated rather than hidden: a service token issued as `admin-api:*` will be refused
 * here and accepted by a sibling that calls `hasScope`. `scopes.test.ts` pins that in both
 * directions so the difference is a recorded decision rather than a surprise.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **AND THE SCOPE NOBODY HAS.** There is no `admin:execute` that a service token can hold. Every
 * action that changes something in another service travels through the approval queue, and an
 * approval names two *human* operators. A service token on this surface can read and it can
 * mirror an audit row; it cannot request, approve or execute. See `server.ts`.
 */

import { ForbiddenError, type Principal } from '@cloudsforge/auth'

/** Read the audit mirror, the approval queue, the flags and the broadcasts. */
export const READ_SCOPE = 'admin:read'
/** Mirror an audit row from another service. Held by every service that writes audit rows. */
export const MIRROR_SCOPE = 'admin:audit:write'

export const ALL_SCOPES: readonly string[] = Object.freeze([READ_SCOPE, MIRROR_SCOPE])

/**
 * Exact scope match. The §3.3h choice, in one line.
 *
 * Deliberately NOT `hasScope` from `@cloudsforge/auth`. See the file header. Neither package is
 * modified; this service simply declines to use the permissive reading on its own surface.
 */
export function hasExactScope(principal: Principal, required: string): boolean {
  return principal.kind === 'service' && principal.scopes.includes(required)
}

export function requireExactScope(principal: Principal, required: string): void {
  if (!hasExactScope(principal, required)) throw new ForbiddenError(required)
}
