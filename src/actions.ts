/**
 * The closed list of operator actions, and what executes each one.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE §3.3g ANSWER: GRANTING A PLATFORM ROLE IS NOT THIS SERVICE'S WRITE TO MAKE.**
 *
 * 18-build-status.md §3.3g records, verified against a running deployment rather than reasoned
 * about, that the estate cannot bootstrap itself: `POST /service-tokens` requires the `admin` role
 * (`identity/src/server.ts:1266`, via `authenticateAdmin` at `:545`), `users.roles` is
 * `text[] not null default '{}'` (`identity/src/migrations.ts:119`), and no route in identity
 * grants a role. All three re-checked here against source; all three are true, and the
 * enumeration was repeated — identity defines 36 routes, `POST /auth/register` hard-codes
 * `['player']` (`identity/src/users.ts:104-106`), and `POST /organisations/:id/memberships`
 * (`identity/src/server.ts:1229`) grants an ORGANISATION role, which SD-03 is explicit is not a
 * platform role. Nothing assigns `users.roles`.
 *
 * The decision, in three parts:
 *
 * **The WRITE belongs to identity.** `users.roles` is identity's column in identity's database.
 * Rule 1 of docs/ecosystem/03 §2 — one database, and no service reads another's — is enforced by
 * a CI check that greps this repository's source for any connection string that is not
 * `ADMIN_API_DATABASE_URL`. So this is not a matter of taste: a version of this service that
 * granted a role by writing to identity would fail its own build, and correctly. The route
 * identity needs is small and is specified at the bottom of this comment.
 *
 * **The AUTHORISATION belongs here, and is built.** Granting `admin` is the most audit-worthy
 * action in the estate — an operator who can grant it can grant it to anyone, including to an
 * account they control — so it is a two-operator action with a mandatory reason code and a
 * hash-chained audit row, exactly like a manual ledger reversal. That machinery exists in this
 * repository, is exercised by the actions that DO have an upstream route, and `identity.role.grant`
 * is a first-class entry in the catalogue below. What it does not have is an executor, because
 * there is nothing to call.
 *
 * **The BOOTSTRAP belongs to neither, and that is deliberate.** A service that can mint its own
 * first `admin` is a service whose compromise grants the estate — and this service's own
 * approval queue cannot authorise the first grant, because approving requires an operator who
 * already holds the role. Bootstrap therefore stays outside every service: one
 * `update users set roles = array['admin']` under the database owner's credentials, which is what
 * `scripts/slice-verify.sh` already does and asserts. That is the correct home for a step that
 * should require physical access to the database and should appear in a runbook rather than an
 * API.
 *
 * **So `POST /v1/approvals` with `action: 'identity.role.grant'` answers 501**, naming the route
 * identity must grow, rather than accepting a request the queue can never execute. A queue that
 * accepts work it cannot do is a queue that lies to the operator who is waiting on it — and it
 * would produce an approval sitting at `approved` for ever, which reads in the audit as two
 * operators having authorised something that never happened.
 *
 * The route identity needs, specified so that the day it lands this file changes in one place:
 *
 *     PUT /internal/users/:id/roles      body: { roles: string[], actor: string, reason: string }
 *     guard: a SERVICE token holding `identity:admin` — not `authenticateAdmin`, which refuses a
 *            service token outright (`identity/src/server.ts:539-541`) and would therefore make
 *            the route unreachable from here for the same reason the bootstrap is unreachable now
 *     audit: an `identity.role.changed` row in the same transaction, per SD-15's Identity row
 *
 * With that route in place, `EXECUTORS['identity.role.grant']` becomes ten lines and the 501 test
 * below fails — which is the point of writing the test that way.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **WHY THE CATALOGUE IS DATA AND NOT A SWITCH.** `server.ts` reads `ACTIONS` to validate a
 * request, `jobs.ts` reads it to decide what may be retried, and `routeidempotency.test.ts` reads
 * the file to prove nothing was added without a decision. An action added tomorrow that names no
 * executor, no reason for having none, and no subject kind will not typecheck.
 */

import type { Approval } from './approvals.ts'
import type { BillingClient, LedgerClient, MarketClient } from './upstreams.ts'

export interface ExecutionContext {
  readonly approval: Approval
  /** The approver's own bearer, forwarded where the upstream accepts one. See `upstreams.ts`. */
  readonly operatorBearer: string
  /** The approver's principal — `user:<uuid>`. Never a service, and never the requester. */
  readonly operator: string
  readonly correlationId: string
  readonly ledger: LedgerClient
  readonly market: MarketClient
  readonly billing: BillingClient
}

export type Executor = (ctx: ExecutionContext) => Promise<Record<string, unknown>>

export interface ActionSpec {
  /** What kind of thing the action names. Becomes `audit_events.subject_kind`. */
  readonly subjectKind: string
  /** Which upstream performs it. `null` when nothing can. */
  readonly upstream: 'ledger' | 'market' | 'billing' | null
  /** One line an operator console shows beside the action. */
  readonly summary: string
  /**
   * The route this executes, cited. `null` means the route does not exist — and then
   * `blockedReason` says so and the request is refused at creation with 501.
   */
  readonly route: string | null
  readonly blockedReason: string | null
  /** Required parameter names, validated before the request is accepted. */
  readonly requiredParams: readonly string[]
}

export const ACTIONS: Readonly<Record<string, ActionSpec>> = Object.freeze({
  'ledger.entry.reverse': {
    subjectKind: 'ledger_entry',
    upstream: 'ledger',
    summary: 'Reverse a ledger entry with a new balanced journal entry. Never an UPDATE (AD-06).',
    route: 'POST /entries/:id/reverse — ledger/src/server.ts:394, scope ledger:post',
    blockedReason: null,
    requiredParams: ['description'],
  },
  'market.moderation.case.resolve': {
    subjectKind: 'moderation_case',
    upstream: 'market',
    summary: 'Uphold or dismiss a marketplace moderation case.',
    route: 'POST /v1/moderation/cases/:id/resolve — market/src/server.ts:1086, market:admin or role:admin',
    blockedReason: null,
    requiredParams: ['state'],
  },
  'billing.entitlement.revoke': {
    subjectKind: 'entitlement',
    upstream: 'billing',
    summary: 'Revoke an entitlement, optionally refunding it.',
    route: 'POST /entitlements/:id/revoke — billing/src/server.ts:544, billing:grant or role:admin',
    blockedReason: null,
    requiredParams: ['reason'],
  },
  'identity.role.grant': {
    subjectKind: 'user',
    upstream: null,
    summary: 'Grant a platform role. THE MOST AUDIT-WORTHY ACTION IN THE ESTATE — see the header.',
    route: null,
    blockedReason:
      'identity has no route that assigns users.roles. All 36 of its route definitions were ' +
      'enumerated: POST /auth/register hard-codes [\'player\'] (identity/src/users.ts:104-106) and ' +
      'POST /organisations/:id/memberships grants an organisation role, which SD-03 states is not ' +
      'a platform role. This service will not write to identity\'s database to work around it — ' +
      'rule 1, one database per service, checked in CI. It needs ' +
      'PUT /internal/users/:id/roles behind a service token holding identity:admin.',
    requiredParams: ['role'],
  },
})

export type ActionName = keyof typeof ACTIONS

export function isKnownAction(name: string): name is ActionName {
  return Object.prototype.hasOwnProperty.call(ACTIONS, name)
}

/** Actions that can actually run. The complement is the gap list, and it is one entry long. */
export const EXECUTABLE_ACTIONS: readonly string[] = Object.freeze(
  Object.entries(ACTIONS)
    .filter(([, spec]) => spec.route !== null)
    .map(([name]) => name),
)

export const BLOCKED_ACTIONS: readonly string[] = Object.freeze(
  Object.entries(ACTIONS)
    .filter(([, spec]) => spec.route === null)
    .map(([name]) => name),
)

function requireString(params: Record<string, unknown>, key: string): string {
  const value = params[key]
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`params.${key} must be a non-empty string`)
  }
  return value
}

/**
 * The executors, by action name.
 *
 * Every one of them is idempotent at the upstream: the ledger reversal derives its idempotency key
 * from the approval id, and the other two are state transitions their upstreams claim
 * conditionally. That matters because `recordExecution` and the upstream call cannot be one
 * transaction — one of them is an HTTP request — so a crash between them must be safe to retry.
 * `jobs.ts` retries exactly this way.
 */
export const EXECUTORS: Readonly<Record<string, Executor>> = Object.freeze({
  'ledger.entry.reverse': async (ctx) => {
    const entry = await ctx.ledger.reverseEntry({
      entryId: ctx.approval.subjectId,
      // Derived from the approval id, so a retry of the same approval replays the ledger's stored
      // response rather than posting a second reversal. An approval authorises ONE reversal.
      idempotencyKey: `admin-api:approval:${ctx.approval.id}`,
      description: requireString(ctx.approval.params, 'description'),
      correlationId: ctx.correlationId,
      operator: ctx.operator,
      approvalId: ctx.approval.id,
    })
    return { entryId: entry.id, reversesEntryId: entry.reversesEntryId, replayed: entry.replayed }
  },

  'market.moderation.case.resolve': async (ctx) => {
    const state = requireString(ctx.approval.params, 'state')
    if (state !== 'upheld' && state !== 'dismissed') {
      throw new Error('params.state must be "upheld" or "dismissed"')
    }
    const resolved = await ctx.market.resolveCase({
      caseId: ctx.approval.subjectId,
      state,
      notes: `${ctx.approval.reasonCode}: ${ctx.approval.reason} (admin-api approval ${ctx.approval.id})`,
      correlationId: ctx.correlationId,
      operatorBearer: ctx.operatorBearer,
    })
    return { caseId: resolved.id, state: resolved.state }
  },

  'billing.entitlement.revoke': async (ctx) => {
    const result = await ctx.billing.revokeEntitlement({
      entitlementId: ctx.approval.subjectId,
      reason: requireString(ctx.approval.params, 'reason'),
      refund: ctx.approval.params['refund'] === true,
      correlationId: ctx.correlationId,
      operatorBearer: ctx.operatorBearer,
    })
    return { alreadyRevoked: result.alreadyRevoked, reversalEntryId: result.reversalEntryId ?? null }
  },
})
