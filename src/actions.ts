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
 * is a first-class entry in the catalogue below. **It now has an executor**, because identity has
 * built the route specified at the bottom of this comment. See §"THE ROUTE LANDED" below.
 *
 * **The BOOTSTRAP belongs to neither, and that is deliberate.** A service that can mint its own
 * first `admin` is a service whose compromise grants the estate — and this service's own
 * approval queue cannot authorise the first grant, because approving requires an operator who
 * already holds the role. Bootstrap therefore stays outside every service: one
 * `update users set roles = array['admin']` under the database owner's credentials, which is what
 * `deploy/scripts/estate-bootstrap.sh:102` already does. That is the correct home for a step that
 * should require physical access to the database and should appear in a runbook rather than an
 * API.
 *
 * **BUT THE STATEMENT IS THE WRONG SHAPE, AND THAT IS A SEPARATE DEFECT.** Where it runs is right;
 * what it is is not. It is **repeatable** — nothing makes the second run differ from the first, so
 * it is not a bootstrap but a permanent superuser lever available for ever to anyone who reaches
 * the database. It is **unaudited** — `identity/src/migrations.ts:119` is `roles text[] not null
 * default '{}'` and nothing else, so the most consequential write in the estate is the only one
 * with no trail. And it is **unproven** — nothing goes red if identity, or this service, grows a
 * route that does the same thing.
 *
 * The fix is one-shot enforcement in the SCHEMA, where a bug, a migration or an operator holding a
 * connection cannot route around it — the discipline `engagement_policies_raise_needs_approval`
 * below and `ledger`'s deferred balance constraint already follow. Two halves, both in identity,
 * because `users.roles` is identity's column:
 *
 *     create table platform_role_grants (
 *       id uuid primary key default gen_random_uuid(),
 *       user_id uuid not null references users (id),
 *       role text not null,
 *       source text not null,            -- 'bootstrap' | 'approval'
 *       approval_id uuid,                -- THIS service's approval id, for source='approval'
 *       actor text not null,
 *       reason text not null,
 *       granted_at timestamptz not null default now(),
 *       constraint platform_role_grants_source_known check (source in ('bootstrap','approval')),
 *       constraint platform_role_grants_approval_pairing
 *         check ((source = 'approval') = (approval_id is not null))
 *     );
 *
 *     -- ONE bootstrap grant per database, for ever. The second insert fails at the index, in any
 *     -- transaction, from any client, including psql. This is the whole security property.
 *     create unique index platform_role_grants_one_bootstrap
 *       on platform_role_grants (source) where source = 'bootstrap';
 *
 *     -- ...and a role cannot be gained without a grant row that authorises it. DEFERRED, so the
 *     -- grant and the role may be written in either order inside one transaction; a bare
 *     -- `update users set roles = array['admin']` from psql therefore fails at COMMIT.
 *     create constraint trigger users_roles_need_a_grant
 *       after insert or update of roles on users
 *       deferrable initially deferred for each row
 *       execute function users_roles_need_a_grant();
 *
 * The property that buys: **an environment gets exactly one bootstrapped administrator, and every
 * administrator after the first carries an approval id** — which is to say, two operators'
 * signatures out of this service's queue. Four eyes still needs two operators, so capping admins
 * at one would be wrong; capping *unapproved* admins at one is the invariant that was wanted.
 *
 * `bootstrap.test.ts` proves the half of this that lives here: that this service is not, and
 * cannot silently become, the escalation route. The identity half and the runbook half are
 * reported to the repositories that own them.
 *
 * **`POST /v1/approvals` with `action: 'identity.role.grant'` USED TO ANSWER 501**, naming the
 * route identity had to grow rather than accepting a request the queue could never execute. A
 * queue that accepts work it cannot do lies to the operator waiting on it, and would leave an
 * approval sitting at `approved` for ever — which reads in the audit as two operators having
 * authorised something that never happened.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE ROUTE LANDED, SO THE 501 IS GONE AND THE ACTION EXECUTES.**
 *
 * `micro-identity` built it in the shape specified below: `PUT /internal/users/:id/roles`
 * (`identity/src/server.ts:1584`), gated on a SERVICE token holding `identity:admin` (`:626`),
 * writing a `platform_role_grants` row with `source='approval'` in the same transaction as the
 * `users.roles` update, behind a deferred constraint trigger that refuses the update without one
 * and a partial unique index that spends the single `bootstrap` slot for ever.
 *
 * **It was not the "ten lines" the last paragraph of this comment predicted.** `setPlatformRoles`
 * REPLACES the role set rather than adding to it, so `roles: [role]` would have revoked `player`
 * from every operator it promoted. The executor unions instead; `BASE_PLATFORM_ROLE` and the
 * executor's own header carry that argument, and two tests break on the two silent failure modes.
 *
 * **What did NOT change: this service is still not the escalation route.** Executing requires an
 * approval two DISTINCT operators signed, which requires an administrator to already exist. The
 * first still comes from the deploy-time bootstrap. `bootstrap.test.ts` holds that line.
 *
 * **STILL OWED BY `micro-deploy`:** admin-api's service token does not carry `identity:admin`
 * (`deploy/compose/docker-compose.estate.yml:301` grants it `ledger:read`, `market:read`,
 * `market:admin`, `billing:read`). Until it does, this executor is correct and will 403 at
 * identity in the estate. Reported there rather than worked around here.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The route as it was specified, kept because the shape it names is the shape that was built:
 *
 *     PUT /internal/users/:id/roles      body: { roles: string[], actor: string, reason: string,
 *                                                approvalId: string }
 *     guard: a SERVICE token holding `identity:admin` — not `authenticateAdmin`, which refuses a
 *            service token outright (`identity/src/server.ts:540`) and would therefore make
 *            the route unreachable from here for the same reason the bootstrap is unreachable now
 *     write: a `platform_role_grants` row with `source = 'approval'` and that `approvalId`, in the
 *            SAME transaction as the `users.roles` update — the deferred trigger above refuses the
 *            update otherwise, so the audit trail cannot be skipped by a handler that forgets it
 *     audit: an `identity.role.changed` row in the same transaction, per SD-15's Identity row
 *
 * `identity:admin` **is now in `contracts-auth`'s registry** (`contracts` commit 95952c4,
 * "register identity:admin — the scope micro-identity's role gate demands"), registered in step
 * with the gate that demands it rather than ahead of it — which is the discipline the registry's
 * two deprecated entries exist to record.
 *
 * The 501 test below did fail on the day this landed, which is the point of having written it that
 * way. It was changed to assert the new behaviour, deliberately and in the open, rather than
 * deleted.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **WHY THE CATALOGUE IS DATA AND NOT A SWITCH.** `server.ts` reads `ACTIONS` to validate a
 * request, `jobs.ts` reads it to decide what may be retried, and `routeidempotency.test.ts` reads
 * the file to prove nothing was added without a decision. An action added tomorrow that names no
 * executor, no reason for having none, and no subject kind will not typecheck.
 */

import type { Approval } from './approvals.ts'
import type { BillingClient, IdentityClient, LedgerClient, MarketClient } from './upstreams.ts'
import {
  claimTransfer,
  engagementSubjectOf,
  ENGAGEMENT_SERVICES,
  ENGAGEMENT_TREASURY_SUBJECT,
  markTransferPosted,
  parseCapShards,
  parseShards,
  parseWei,
  setFeeRecycle,
  setPolicy,
  type Db,
} from './engagement.ts'

/**
 * The role every registered user holds, preserved across a grant.
 *
 * `identity/src/platformRoles.ts:52` is `PLATFORM_ROLES = ['player', 'admin']`, and
 * `POST /auth/register` hard-codes `['player']`. Identity's role write REPLACES the set rather
 * than adding to it, so this is unioned into every grant — see `EXECUTORS['identity.role.grant']`
 * for the full argument and for why it is a named constant rather than a literal buried in a call.
 */
export const BASE_PLATFORM_ROLE = 'player'

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
  readonly identity: IdentityClient
  /**
   * This service's own database, for the executors whose upstream IS this service — the
   * engagement policy write lands in `engagement_policies`, and the engagement transfer's
   * cap-checked record lands in `engagement_transfers` before the ledger is asked to move
   * anything. Added with the engagement actions; every earlier executor ignores it.
   */
  readonly sql: Db
}

export type Executor = (ctx: ExecutionContext) => Promise<Record<string, unknown>>

export interface ActionSpec {
  /** What kind of thing the action names. Becomes `audit_events.subject_kind`. */
  readonly subjectKind: string
  /** Which upstream performs it. `'admin-api'` when this service's own tables are the upstream;
   *  `null` when nothing can perform it at all. */
  readonly upstream: 'ledger' | 'market' | 'billing' | 'identity' | 'admin-api' | null
  /**
   * What authorises the action. `'two-operator'` is the queue: request, second operator, execute.
   * `'read'` is doc 21 §6's third row — an action the catalogue lists so the console renders it,
   * whose approval column reads "none (read)", and which the queue therefore REFUSES with the GET
   * route to call instead: a read that consumed two operators' signatures would train operators
   * to sign reflexively, which is the end of the four-eyes control by other means.
   */
  readonly approval: 'two-operator' | 'read'
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
    approval: 'two-operator',
    summary: 'Reverse a ledger entry with a new balanced journal entry. Never an UPDATE (AD-06).',
    route: 'POST /entries/:id/reverse — ledger/src/server.ts:394, scope ledger:post',
    blockedReason: null,
    requiredParams: ['description'],
  },
  'market.moderation.case.resolve': {
    subjectKind: 'moderation_case',
    upstream: 'market',
    approval: 'two-operator',
    summary: 'Uphold or dismiss a marketplace moderation case.',
    route: 'POST /v1/moderation/cases/:id/resolve — market/src/server.ts:1086, market:admin or role:admin',
    blockedReason: null,
    requiredParams: ['state'],
  },
  'billing.entitlement.revoke': {
    subjectKind: 'entitlement',
    upstream: 'billing',
    approval: 'two-operator',
    summary: 'Revoke an entitlement, optionally refunding it.',
    route: 'POST /entitlements/:id/revoke — billing/src/server.ts:544, billing:grant or role:admin',
    blockedReason: null,
    requiredParams: ['reason'],
  },
  // ── The engagement treasury, docs/ecosystem/21 §6. Three actions, one table there, one table
  //    row here. §8's build order is why these exist before any grant machinery does: nothing may
  //    move a Shard before the caps exist, and the caps are migrations.ts version 8.
  'engagement.transfer': {
    subjectKind: 'engagement_account',
    upstream: 'ledger',
    approval: 'two-operator',
    summary:
      'Fund a service’s engagement account from platform:engagement-treasury. Refused above the ' +
      'policy cap BY THE SCHEMA (engagement_transfers_within_cap), executed as one balanced ' +
      'micro-ledger entry whose accounts are created idempotently on first use.',
    route: 'POST /entries — ledger/src/server.ts:346, scope ledger:post',
    blockedReason: null,
    requiredParams: ['service', 'amountShards'],
  },
  'engagement.policy.set': {
    subjectKind: 'engagement_policy',
    upstream: 'admin-api',
    approval: 'two-operator',
    summary:
      'RAISE an engagement cap: a per-service transfer ceiling, foresight’s seed sizes, or the ' +
      'fee-recycle percentage. Raising needs two operators; LOWERING needs one and does not pass ' +
      'through this queue — PUT /v1/engagement/policies/:service, the devplatform quota asymmetry ' +
      '(devplatform/src/server.ts:981: the direction is the authority).',
    route: 'PUT /v1/engagement/policies/:service — admin-api/src/engagement.ts:227 setPolicy, the same write this executor performs with the approval id attached',
    blockedReason: null,
    requiredParams: ['service'],
  },
  'engagement.report': {
    subjectKind: 'engagement_account',
    upstream: 'ledger',
    approval: 'read',
    summary:
      'Balances and spend per service, read straight off the ledger. No approval — 21 §6’s ' +
      '"none (read)" — so the queue refuses this and the console calls the GET instead.',
    route: 'GET /v1/engagement/report — this service; balances via GET /accounts/:subject/balances — ledger/src/server.ts:499, scope ledger:read',
    blockedReason: null,
    requiredParams: [],
  },
  /**
   * **THE ROUTE THIS ENTRY SPECIFIED NOW EXISTS, SO THE BLOCK IS LIFTED.**
   *
   * `blockedReason` used to describe a route identity did not have. `micro-identity` has since
   * built exactly it — `PUT /internal/users/:id/roles`, gated on a SERVICE token holding
   * `identity:admin` (`identity/src/server.ts:1584,626`), writing a `platform_role_grants` row
   * with `source = 'approval'` in the same transaction as the `users.roles` update, behind a
   * deferred constraint trigger that refuses the update if that row is missing.
   *
   * So this becomes an executable action. **What does NOT change is where the first administrator
   * comes from.** That is still the deploy-time bootstrap, one-shot, refused on re-run by a
   * partial unique index on `source='bootstrap'` and an immutability trigger that stops a `DELETE`
   * re-arming it. This service is not the escalation route and must not become one: executing here
   * requires an approval that two DISTINCT operators signed, which requires an operator to exist
   * already. `bootstrap.test.ts` holds that line.
   *
   * Every administrator after the first therefore carries an `approvalId`, and identity's CHECK
   * pairs `source='approval'` to it as an EQUALITY rather than an implication — so an executor
   * that omitted it would be refused by identity's database rather than quietly creating an
   * unattributed admin. The executor below passes it, and a test asserts it is passed.
   */
  'identity.role.grant': {
    subjectKind: 'user',
    upstream: 'identity',
    approval: 'two-operator',
    summary: 'Grant a platform role. THE MOST AUDIT-WORTHY ACTION IN THE ESTATE — see the header.',
    route: 'PUT /internal/users/:id/roles — identity/src/server.ts:1584, scope identity:admin (SERVICE token only)',
    blockedReason: null,
    requiredParams: ['role'],
  },
})

export type ActionName = keyof typeof ACTIONS

export function isKnownAction(name: string): name is ActionName {
  return Object.prototype.hasOwnProperty.call(ACTIONS, name)
}

/** Actions the queue can actually run: a route exists AND two operators are what authorises it. */
export const EXECUTABLE_ACTIONS: readonly string[] = Object.freeze(
  Object.entries(ACTIONS)
    .filter(([, spec]) => spec.route !== null && spec.approval === 'two-operator')
    .map(([name]) => name),
)

export const BLOCKED_ACTIONS: readonly string[] = Object.freeze(
  Object.entries(ACTIONS)
    .filter(([, spec]) => spec.route === null)
    .map(([name]) => name),
)

/**
 * Actions the catalogue lists for the console that the QUEUE refuses: reads. The refusal at
 * `POST /v1/approvals` names the GET to call, the same way a blocked action's 501 names the
 * missing upstream route — a queue that accepted a read would spend two operators' signatures
 * on something that changes nothing, which devalues every signature it collects.
 */
export const READ_ACTIONS: readonly string[] = Object.freeze(
  Object.entries(ACTIONS)
    .filter(([, spec]) => spec.approval === 'read')
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

  /**
   * Treasury → engagement:<service>, in three steps whose order is the safety argument:
   *
   *   1. CLAIM the transfer row. The insert runs under `engagement_transfers_within_cap`, so the
   *      cap binds BEFORE any money is asked to move — 21 §7.3 — and `unique (approval_id)`
   *      makes one approval one transfer for ever.
   *   2. POST the ledger entry, idempotent on the approval id: a crash between 1 and 2 retries
   *      into a replay, never a second entry. The inline account blocks are what create both
   *      engagement accounts idempotently on first use (ledger ensureAccount, accounts.ts:100).
   *   3. MARK the row posted with the entry id — from here `posted` and the entry id are one
   *      fact (`engagement_transfers_posted_names_entry`), which is 21 §7.4's pairing.
   *
   * Both accounts are `equity` under purpose `treasury`: the programme is the platform's own
   * money earmarked, not revenue and not a user liability, and an empty treasury refuses the
   * debit at the ledger's overdraft trigger rather than going negative — funding must have
   * arrived through the front door (mined-EMBER conversions, 21 §3) first.
   */
  'engagement.transfer': async (ctx) => {
    const service = requireString(ctx.approval.params, 'service')
    if (!ENGAGEMENT_SERVICES.includes(service)) {
      throw new Error(`params.service must be one of ${ENGAGEMENT_SERVICES.join(', ')}`)
    }
    const amount = parseShards(requireString(ctx.approval.params, 'amountShards'))

    const claimed = await ctx.sql.begin(async (tx) => ({
      value: await claimTransfer(tx, { service, amountShards: amount, approvalId: ctx.approval.id }),
    }))
    if (claimed.value.state === 'posted') {
      return {
        transferId: claimed.value.id,
        service,
        amountShards: claimed.value.amountShards,
        ledgerEntryId: claimed.value.ledgerEntryId,
        replayed: true,
      }
    }

    const entry = await ctx.ledger.postEntry({
      kind: 'transfer',
      idempotencyKey: `admin-api:approval:${ctx.approval.id}`,
      description: `engagement transfer: treasury → engagement:${service} (${ctx.approval.reasonCode})`,
      correlationId: ctx.correlationId,
      operator: ctx.operator,
      approvalId: ctx.approval.id,
      postings: [
        {
          direction: 'debit',
          amount: amount.toString(),
          assetCode: 'SHARD',
          sequence: 0,
          account: {
            subject: ENGAGEMENT_TREASURY_SUBJECT,
            assetCode: 'SHARD',
            purpose: 'treasury',
            type: 'equity',
          },
        },
        {
          direction: 'credit',
          amount: amount.toString(),
          assetCode: 'SHARD',
          sequence: 1,
          account: {
            subject: engagementSubjectOf(service),
            assetCode: 'SHARD',
            purpose: 'treasury',
            type: 'equity',
          },
        },
      ],
    })

    const posted = await ctx.sql.begin(async (tx) => ({
      value: await markTransferPosted(tx, ctx.approval.id, entry.id),
    }))
    return {
      transferId: posted.value?.id ?? claimed.value.id,
      service,
      amountShards: amount.toString(),
      ledgerEntryId: entry.id,
      replayed: entry.replayed,
    }
  },

  /**
   * The RAISE path. `setPolicy`/`setFeeRecycle` are the same functions the single-operator
   * lowering route calls — one write path, with the approval id attached here so the
   * `engagement_raise_needs_approval` trigger finds a fresh approved approval to satisfy it.
   * `service: 'platform'` addresses the fee recycle, since the recycle is platform-wide and the
   * six service names are taken (and pinned by the schema's closed list).
   */
  'engagement.policy.set': async (ctx) => {
    const service = requireString(ctx.approval.params, 'service')
    const params = ctx.approval.params

    if (service === 'platform') {
      const bps = requireString(params, 'recycleBps')
      if (!/^\d{1,4}$/.test(bps)) throw new Error('params.recycleBps must be a decimal string of basis points')
      const result = await ctx.sql.begin(async (tx) => ({
        value: await setFeeRecycle(tx, {
          recycleBps: Number(bps),
          operator: ctx.operator,
          approvalId: ctx.approval.id,
          correlationId: ctx.correlationId,
        }),
      }))
      return { feeRecycle: { ...result.value } }
    }

    const change = {
      ...(typeof params['transferCapShards'] === 'string'
        ? { transferCapShards: parseCapShards(params['transferCapShards']) }
        : {}),
      ...(typeof params['seedPerMarketWei'] === 'string'
        ? { seedPerMarketWei: parseWei(params['seedPerMarketWei']) }
        : {}),
      ...(typeof params['seedPerDayWei'] === 'string'
        ? { seedPerDayWei: parseWei(params['seedPerDayWei']) }
        : {}),
    }
    if (Object.keys(change).length === 0) {
      throw new Error(
        'engagement.policy.set needs at least one of transferCapShards, seedPerMarketWei+seedPerDayWei',
      )
    }
    const result = await ctx.sql.begin(async (tx) => ({
      value: await setPolicy(tx, {
        service,
        change,
        operator: ctx.operator,
        approvalId: ctx.approval.id,
        correlationId: ctx.correlationId,
      }),
    }))
    return { policy: { ...result.value } }
  },

  /**
   * Grant a platform role. The most consequential call this service makes.
   *
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * **THE ROUTE REPLACES THE ROLE SET; THIS ACTION ADDS ONE ROLE. THE MISMATCH IS HANDLED HERE
   * AND IT IS THE REASON THIS IS NOT THE "TEN LINES" THIS FILE'S HEADER PREDICTED.**
   *
   * `setPlatformRoles` (`identity/src/platformRoles.ts:116`) takes the COMPLETE set the user is to
   * end up with and computes `granted` and `revoked` by diffing against what they hold. So a naive
   * `roles: [role]` would REVOKE every other role the user has. That is not hypothetical:
   * `PLATFORM_ROLES` is `['player', 'admin']` (`:52`) and `POST /auth/register` hard-codes
   * `['player']`, so **every** user has `player` — and promoting an operator to `admin` by sending
   * `['admin']` would demote them out of the ordinary user role in the same call. A privilege
   * REMOVAL disguised as a grant, on the estate's most audit-worthy path.
   *
   * The union is therefore built explicitly, and `player` is preserved by name.
   *
   * **THE HONEST COST OF DOING IT THIS WAY.** It encodes identity's role vocabulary in this
   * repository, which is exactly the kind of drift this estate keeps producing. It is done anyway
   * because the alternative is worse — silently revoking roles — and because identity exposes no
   * route that reads another user's current roles: `GET /internal/users/:id/role-grants` returns
   * the grant HISTORY, not the live set, and a history cannot be replayed into a set because the
   * bootstrap grant and any direct write are not in it.
   *
   * **REPORTED TO `micro-identity`, not worked around further:** the write wants to be a delta
   * (`grant`/`revoke`) or to be accompanied by a read of the current set. Until one of those
   * exists, this union is the safe reading, and `actions.test.ts` pins the exact body sent so the
   * day the vocabulary gains a third role, the pin is what a reader is sent to.
   *
   * **THE APPROVAL ID IS NOT OPTIONAL AND IS NOT DECORATION.** Identity pairs `source='approval'`
   * to `approval_id` with a CHECK written as an EQUALITY, so a grant sent without one is refused
   * by identity's database rather than creating an unattributed administrator. It is passed here,
   * and `actions.test.ts` asserts it is passed — because the failure mode of forgetting it is an
   * upstream 400 at execution time, which is the worst moment to discover it.
   *
   * **THIS IS STILL NOT THE ESCALATION ROUTE.** Reaching this code requires an approval that two
   * DISTINCT operators signed (`approvals_no_self_approval`), which requires an administrator to
   * exist already. The FIRST administrator comes from identity's deploy-time bootstrap, one-shot
   * and refused on re-run by a partial unique index that no client can route around.
   * `bootstrap.test.ts` holds that line from this side.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   */
  'identity.role.grant': async (ctx) => {
    const role = requireString(ctx.approval.params, 'role')

    const change = await ctx.identity.setRoles({
      userId: ctx.approval.subjectId,
      // The union, not the bare role. See above — `[role]` alone revokes `player`.
      roles: [...new Set([BASE_PLATFORM_ROLE, role])],
      // The APPROVER, not the requester. Identity records this as who authorised the promotion,
      // and it is the same principal this service's own hash-chained audit row names.
      actor: ctx.operator,
      reason: `${ctx.approval.reasonCode}: ${ctx.approval.reason}`,
      approvalId: ctx.approval.id,
      correlationId: ctx.correlationId,
    })

    return {
      userId: ctx.approval.subjectId,
      roles: [...change.roles],
      granted: [...change.granted],
      revoked: [...change.revoked],
    }
  },
})
