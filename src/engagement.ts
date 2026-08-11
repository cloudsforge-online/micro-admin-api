/**
 * The engagement treasury's operator state — docs/ecosystem/21, phase 1.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT LIVES HERE AND WHAT DELIBERATELY DOES NOT.**
 *
 * The money is in `micro-ledger`: `platform:engagement-treasury` and `engagement:<service>` are
 * ordinary ledger accounts (the grammar is `contracts/packages/money/src/index.ts`, the
 * accounts are rows in the ledger's unchanged chart — 21 §4 requires zero ledger schema change and
 * gets it). This file holds what 21 §4 assigns to admin-api because "it already owns cross-service
 * operator state": the caps, the fee-recycle percentage, and the record that every approved
 * transfer produced exactly one ledger entry.
 *
 * **THE ASYMMETRY, STATED ONCE.** Raising any cap is an `engagement.policy.set` approval — two
 * operators — and the schema itself refuses a raise that names no fresh approved approval
 * (`engagement_raise_needs_approval`, migrations.ts version 8). Lowering is one operator on
 * `PUT /v1/engagement/policies/:service`, because a cap the capped programme can quietly raise is
 * not a cap, while an operator narrowing the blast radius is doing the platform's work for it.
 * That is `micro-devplatform`'s quota decision (`devplatform/src/server.ts`, "A QUOTA THE
 * QUOTA'D PARTY CAN RAISE IS NOT A QUOTA … THE DIRECTION IS THE AUTHORITY"), applied to the money
 * that funds empty rooms.
 *
 * **THE CEILINGS ARE IN THE SCHEMA AND MIRRORED HERE AS CONSTANTS** so a route can refuse with a
 * sentence before the constraint refuses with an errcode. The numbers must match migrations.ts —
 * version 8 as amended by version 13 — exactly; `engagement.test.ts` proves each constant against
 * the live constraint by writing ceiling-plus-one through a raw connection and watching it refuse.
 *
 * **THE UNIT IS EMBER WEI, AND IT WAS SHARD UNTIL 2026-08-10** — micro-org#226, migration 13. The
 * cap and the transfer record bound a movement between two LEDGER accounts, and the account they
 * bound is funded in EMBER by the only code that funds it (`feeRecyclePostings` in
 * `billing/src/ledger.ts`, whose asset is billing's `settlementAsset: 'EMBER'`). A cap in a unit
 * the account cannot hold is a cap that cannot be compared with the balance it governs; docs 21 §2
 * has said "denominated in EMBER" since 2026-08-07 and this file now agrees with it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Sql, TransactionSql } from 'postgres'
import type { IssuableAssetCode } from '@cloudsforge/contracts-chain'
import type { EntryKind } from '@cloudsforge/contracts-money'
import { appendAudit } from './audit.ts'

export type Db = Sql
export type Tx = TransactionSql

/**
 * The asset every engagement posting is denominated in, spelled once — micro-org#226.
 *
 * `IssuableAssetCode` — `Exclude<AssetCode, 'SHARD'>` in contracts-chain — and not a string. Both
 * legs of `engagement.transfer` read `'SHARD'` until 2026-08-10, which executed cleanly because
 * `micro-ledger`'s retired-asset gate is scoped to `ACQUISITION_KINDS` and deliberately leaves
 * `transfer` legal so the 13 live SHARD balances can be drained (ledger/src/entries.ts). Nothing
 * would have failed; the programme would simply have moved a retired asset while the treasury it
 * spends is funded in EMBER. The type is what stops that returning: a build that named SHARD here
 * would not compile.
 */
export const ENGAGEMENT_ASSET: IssuableAssetCode = 'EMBER'

/**
 * The ledger kind every engagement transfer is posted under, spelled once — micro-org#424.
 *
 * `transfer` because that is what the movement is: value going from one treasury account to
 * another, both `equity` under purpose `treasury`, neither of them a spend of the programme's
 * money on anything yet. `treasury_spend` is what a service posts when it later pays a grant OUT
 * of the account this funds (`ENGAGEMENT_GRANT_KIND` in contracts-money), and using it here would
 * count the same EMBER as spent twice.
 *
 * `EntryKind` and not a string, for the same reason `ENGAGEMENT_ASSET` is `IssuableAssetCode`: the
 * ledger's vocabulary is closed and refuses an unknown kind before it opens a transaction, so a
 * kind invented at this call site would move nothing and say nothing. Named here rather than
 * written at the call site so that the executor and the test that checks it are the same value.
 */
export const ENGAGEMENT_TRANSFER_KIND: EntryKind = 'transfer'

/** The services 21 §1 names. The schema pins the same list; this is the route's copy. */
export const ENGAGEMENT_SERVICES: readonly string[] = Object.freeze([
  'foresight',
  'market',
  'worlds',
  'aetherholm',
  'emberkin',
  'trade',
])

/** The ledger subject each policy row funds. Spelled once, from 21 §4's tree. */
export function engagementSubjectOf(service: string): string {
  return `engagement:${service}`
}

export const ENGAGEMENT_TREASURY_SUBJECT = 'platform:engagement-treasury'

/* The schema ceilings, mirrored. migrations.ts version 8 is the authority; these are the copies
 * the routes use to refuse with a sentence. Each is proven against its constraint by test. */
// 4e25 wei = 40,000,000 EMBER = USD 10M per transfer at EMBER's administered 0.25 — the SAME
// money the 1,000,000,000 Shards this read until 2026-08-10 meant (micro-org#226). Converted at
// migration 13's frozen rate, not relabelled: SHARD has 0 decimals and EMBER has 18.
export const TRANSFER_CAP_CEILING_WEI = 40_000_000_000_000_000_000_000_000n
export const SEED_PER_MARKET_CEILING_WEI = 1_000_000_000_000_000_000_000n // 1,000 EMBER
export const SEED_PER_DAY_CEILING_WEI = 10_000_000_000_000_000_000_000n // 10,000 EMBER
export const FEE_RECYCLE_CEILING_BPS = 2_500 // 25% of platform fee revenue

export class EngagementError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EngagementError'
  }
}

/** A single-operator write tried to RAISE. Its own class so the route answers 403 with the path. */
export class RaiseNeedsApprovalError extends EngagementError {
  constructor(detail: string) {
    super(
      `${detail} — raising an engagement cap requires an approved engagement.policy.set action ` +
        '(two operators); only lowering is a single-operator write (21 §7.7)',
    )
    this.name = 'RaiseNeedsApprovalError'
  }
}

export interface EngagementPolicy {
  readonly service: string
  readonly transferCapWei: string
  readonly seedPerMarketWei: string | null
  readonly seedPerDayWei: string | null
  readonly lastChangeApprovalId: string | null
  readonly updatedAt: string
  readonly updatedBy: string
}

export interface FeeRecyclePolicy {
  readonly recycleBps: number
  readonly lastChangeApprovalId: string | null
  readonly updatedAt: string | null
  readonly updatedBy: string | null
}

interface PolicyRow {
  readonly service: string
  readonly transfer_cap_wei: string
  readonly seed_per_market_wei: string | null
  readonly seed_per_day_wei: string | null
  readonly last_change_approval_id: string | null
  readonly updated_at: Date
  readonly updated_by: string
}

function toPolicy(row: PolicyRow): EngagementPolicy {
  return {
    service: row.service,
    transferCapWei: row.transfer_cap_wei,
    seedPerMarketWei: row.seed_per_market_wei,
    seedPerDayWei: row.seed_per_day_wei,
    lastChangeApprovalId: row.last_change_approval_id,
    updatedAt: row.updated_at.toISOString(),
    updatedBy: row.updated_by,
  }
}

export async function listPolicies(sql: Db | Tx): Promise<readonly EngagementPolicy[]> {
  const rows = await sql<PolicyRow[]>`
    select service, transfer_cap_wei::text, seed_per_market_wei::text, seed_per_day_wei::text,
           last_change_approval_id, updated_at, updated_by
      from engagement_policies order by service
  `
  return rows.map(toPolicy)
}

export async function findPolicy(sql: Db | Tx, service: string): Promise<EngagementPolicy | null> {
  const rows = await sql<PolicyRow[]>`
    select service, transfer_cap_wei::text, seed_per_market_wei::text, seed_per_day_wei::text,
           last_change_approval_id, updated_at, updated_by
      from engagement_policies where service = ${service}
  `
  const row = rows[0]
  return row ? toPolicy(row) : null
}

/**
 * The fee-recycle row, absent-tolerant: the migration seeds it at 0 (21's recorded open decision —
 * pure mined funding until revenue exists), but the test harness truncates, and "no row" and "0"
 * are the same fact to every reader.
 */
export async function readFeeRecycle(sql: Db | Tx): Promise<FeeRecyclePolicy> {
  const rows = await sql<
    { recycle_bps: number; last_change_approval_id: string | null; updated_at: Date; updated_by: string }[]
  >`select recycle_bps, last_change_approval_id, updated_at, updated_by from engagement_fee_recycle`
  const row = rows[0]
  if (!row) return { recycleBps: 0, lastChangeApprovalId: null, updatedAt: null, updatedBy: null }
  return {
    recycleBps: row.recycle_bps,
    lastChangeApprovalId: row.last_change_approval_id,
    updatedAt: row.updated_at.toISOString(),
    updatedBy: row.updated_by,
  }
}

/** The values a policy write may carry. Absent fields keep their current value. */
export interface PolicyChange {
  readonly transferCapWei?: bigint
  readonly seedPerMarketWei?: bigint | null
  readonly seedPerDayWei?: bigint | null
}

function requireWithinCeilings(change: PolicyChange): void {
  if (change.transferCapWei !== undefined) {
    if (change.transferCapWei < 0n || change.transferCapWei > TRANSFER_CAP_CEILING_WEI) {
      throw new EngagementError(
        `transferCapWei must be between 0 and ${TRANSFER_CAP_CEILING_WEI} — the schema ceiling refuses more`,
      )
    }
  }
  const perMarket = change.seedPerMarketWei
  const perDay = change.seedPerDayWei
  if ((perMarket === undefined) !== (perDay === undefined) || (perMarket === null) !== (perDay === null)) {
    throw new EngagementError(
      'seedPerMarketWei and seedPerDayWei travel together — half a seed policy is not a policy',
    )
  }
  if (perMarket !== undefined && perMarket !== null && perDay !== undefined && perDay !== null) {
    if (perMarket <= 0n || perMarket > SEED_PER_MARKET_CEILING_WEI) {
      throw new EngagementError(
        `seedPerMarketWei must be between 1 and ${SEED_PER_MARKET_CEILING_WEI} wei — the schema ceiling refuses more`,
      )
    }
    if (perDay < perMarket || perDay > SEED_PER_DAY_CEILING_WEI) {
      throw new EngagementError(
        `seedPerDayWei must be between seedPerMarketWei and ${SEED_PER_DAY_CEILING_WEI} wei`,
      )
    }
  }
}

function isRaise(current: EngagementPolicy | null, change: PolicyChange): boolean {
  const currentCap = current ? BigInt(current.transferCapWei) : 0n
  if (change.transferCapWei !== undefined && change.transferCapWei > currentCap) return true
  const currentPerMarket = current?.seedPerMarketWei ? BigInt(current.seedPerMarketWei) : null
  const currentPerDay = current?.seedPerDayWei ? BigInt(current.seedPerDayWei) : null
  const nextPerMarket = change.seedPerMarketWei
  const nextPerDay = change.seedPerDayWei
  if (nextPerMarket !== undefined && nextPerMarket !== null) {
    if (currentPerMarket === null || nextPerMarket > currentPerMarket) return true
  }
  if (nextPerDay !== undefined && nextPerDay !== null) {
    if (currentPerDay === null || nextPerDay > currentPerDay) return true
  }
  return false
}

export interface SetPolicyInput {
  readonly service: string
  readonly change: PolicyChange
  /** `user:<uuid>`, from the verified token. */
  readonly operator: string
  /**
   * The approved `engagement.policy.set` approval authorising a RAISE, or null for a
   * single-operator lower. The trigger re-checks; passing null on a raise refuses in both places.
   */
  readonly approvalId: string | null
  readonly correlationId: string | null
}

/**
 * Write a policy row — the ONE write path both the lowering route and the raising executor use.
 *
 * The direction decides the authority (see the header): with `approvalId: null` a raise is refused
 * here with a sentence, and refused again by `engagement_policies_raise_needs_approval` for any
 * writer that skips this function. The audit row commits with the change — SD-15.
 */
export async function setPolicy(tx: Tx, input: SetPolicyInput, now: () => Date = () => new Date()): Promise<EngagementPolicy> {
  if (!ENGAGEMENT_SERVICES.includes(input.service)) {
    throw new EngagementError(
      `service must be one of ${ENGAGEMENT_SERVICES.join(', ')} (got ${input.service})`,
    )
  }
  requireWithinCeilings(input.change)

  const current = await findPolicy(tx, input.service)
  const raising = isRaise(current, input.change)
  if (raising && input.approvalId === null) {
    throw new RaiseNeedsApprovalError(
      `this write raises a cap for engagement:${input.service}`,
    )
  }

  const nextCap = input.change.transferCapWei ?? (current ? BigInt(current.transferCapWei) : 0n)
  const nextPerMarket =
    input.change.seedPerMarketWei !== undefined
      ? input.change.seedPerMarketWei
      : current?.seedPerMarketWei
        ? BigInt(current.seedPerMarketWei)
        : null
  const nextPerDay =
    input.change.seedPerDayWei !== undefined
      ? input.change.seedPerDayWei
      : current?.seedPerDayWei
        ? BigInt(current.seedPerDayWei)
        : null
  // Only a raise stamps a new approval id; a lower keeps the last raise's id so the row always
  // names the approval that authorised its high-water mark, and the trigger's freshness rule
  // ("the id must CHANGE on a raise") stays satisfiable.
  const approvalId = raising ? input.approvalId : (current?.lastChangeApprovalId ?? null)

  const rows = await tx<PolicyRow[]>`
    insert into engagement_policies (
      service, transfer_cap_wei, seed_per_market_wei, seed_per_day_wei,
      last_change_approval_id, updated_at, updated_by
    ) values (
      ${input.service}, ${nextCap.toString()},
      ${nextPerMarket === null ? null : nextPerMarket.toString()},
      ${nextPerDay === null ? null : nextPerDay.toString()},
      ${approvalId}, ${now().toISOString()}::timestamptz, ${input.operator}
    )
    on conflict (service) do update set
      transfer_cap_wei = excluded.transfer_cap_wei,
      seed_per_market_wei = excluded.seed_per_market_wei,
      seed_per_day_wei = excluded.seed_per_day_wei,
      last_change_approval_id = excluded.last_change_approval_id,
      updated_at = excluded.updated_at,
      updated_by = excluded.updated_by
    returning service, transfer_cap_wei::text, seed_per_market_wei::text, seed_per_day_wei::text,
              last_change_approval_id, updated_at, updated_by
  `
  const policy = toPolicy(rows[0]!)

  await appendAudit(
    tx,
    {
      actor: input.operator,
      action: raising ? 'admin.engagement.policy.raised' : 'admin.engagement.policy.lowered',
      subjectKind: 'engagement_policy',
      subjectId: input.service,
      outcome: 'allowed',
      reasonCode: null,
      correlationId: input.correlationId,
      payload: {
        before: current,
        after: policy,
        approvalId: input.approvalId,
      },
    },
    now,
  )
  return policy
}

export interface SetFeeRecycleInput {
  readonly recycleBps: number
  readonly operator: string
  readonly approvalId: string | null
  readonly correlationId: string | null
}

/** The fee-recycle write. Same direction rule, same trigger behind it. */
export async function setFeeRecycle(
  tx: Tx,
  input: SetFeeRecycleInput,
  now: () => Date = () => new Date(),
): Promise<FeeRecyclePolicy> {
  if (!Number.isInteger(input.recycleBps) || input.recycleBps < 0 || input.recycleBps > FEE_RECYCLE_CEILING_BPS) {
    throw new EngagementError(
      `recycleBps must be a whole number between 0 and ${FEE_RECYCLE_CEILING_BPS} — the schema ceiling refuses more`,
    )
  }
  const current = await readFeeRecycle(tx)
  const raising = input.recycleBps > current.recycleBps
  if (raising && input.approvalId === null) {
    throw new RaiseNeedsApprovalError('this write raises the fee-recycle percentage')
  }
  const approvalId = raising ? input.approvalId : current.lastChangeApprovalId

  await tx`
    insert into engagement_fee_recycle (singleton, recycle_bps, last_change_approval_id, updated_at, updated_by)
    values (true, ${input.recycleBps}, ${approvalId}, ${now().toISOString()}::timestamptz, ${input.operator})
    on conflict (singleton) do update set
      recycle_bps = excluded.recycle_bps,
      last_change_approval_id = excluded.last_change_approval_id,
      updated_at = excluded.updated_at,
      updated_by = excluded.updated_by
  `
  await appendAudit(
    tx,
    {
      actor: input.operator,
      action: raising ? 'admin.engagement.recycle.raised' : 'admin.engagement.recycle.lowered',
      subjectKind: 'engagement_policy',
      subjectId: 'fee-recycle',
      outcome: 'allowed',
      reasonCode: null,
      correlationId: input.correlationId,
      payload: { beforeBps: current.recycleBps, afterBps: input.recycleBps, approvalId: input.approvalId },
    },
    now,
  )
  return readFeeRecycle(tx)
}

/* ------------------------------------------------------------------------ transfers */

export interface EngagementTransfer {
  readonly id: string
  readonly service: string
  readonly amountWei: string
  readonly approvalId: string
  readonly ledgerEntryId: string | null
  readonly state: 'posting' | 'posted'
  readonly createdAt: string
  readonly postedAt: string | null
}

interface TransferRow {
  readonly id: string
  readonly service: string
  readonly amount_wei: string
  readonly approval_id: string
  readonly ledger_entry_id: string | null
  readonly state: 'posting' | 'posted'
  readonly created_at: Date
  readonly posted_at: Date | null
}

function toTransfer(row: TransferRow): EngagementTransfer {
  return {
    id: row.id,
    service: row.service,
    amountWei: row.amount_wei,
    approvalId: row.approval_id,
    ledgerEntryId: row.ledger_entry_id,
    state: row.state,
    createdAt: row.created_at.toISOString(),
    postedAt: row.posted_at?.toISOString() ?? null,
  }
}

const TRANSFER_COLUMNS = `id, service, amount_wei::text, approval_id, ledger_entry_id, state,
                          created_at, posted_at`

/**
 * Claim the transfer record for an approval, under the cap trigger.
 *
 * `on conflict (approval_id) do nothing` then re-select: a retried execution finds the row the
 * first attempt claimed — in `posting` if the crash was before the ledger answered (the ledger
 * call replays on its key), in `posted` if it was after (nothing is posted again). One approval,
 * one transfer, whatever the retry schedule does.
 */
export async function claimTransfer(
  tx: Tx,
  input: { readonly service: string; readonly amountWei: bigint; readonly approvalId: string },
): Promise<EngagementTransfer> {
  await tx`
    insert into engagement_transfers (service, amount_wei, approval_id)
    values (${input.service}, ${input.amountWei.toString()}, ${input.approvalId})
    on conflict (approval_id) do nothing
  `
  const rows = await tx<TransferRow[]>`
    select ${tx.unsafe(TRANSFER_COLUMNS)} from engagement_transfers
     where approval_id = ${input.approvalId}
  `
  const row = rows[0]
  if (!row) throw new EngagementError('the transfer record could not be claimed or read')
  return toTransfer(row)
}

/** 21 §7.4's other half: `posted` and the entry id become true together, at most once. */
export async function markTransferPosted(
  tx: Tx,
  approvalId: string,
  ledgerEntryId: string,
  now: () => Date = () => new Date(),
): Promise<EngagementTransfer | null> {
  const rows = await tx<TransferRow[]>`
    update engagement_transfers
       set state = 'posted', ledger_entry_id = ${ledgerEntryId},
           posted_at = ${now().toISOString()}::timestamptz
     where approval_id = ${approvalId} and state = 'posting'
    returning ${tx.unsafe(TRANSFER_COLUMNS)}
  `
  const row = rows[0]
  return row ? toTransfer(row) : null
}

export async function listTransfers(sql: Db | Tx, limit = 100): Promise<readonly EngagementTransfer[]> {
  const rows = await sql<TransferRow[]>`
    select ${sql.unsafe(TRANSFER_COLUMNS)} from engagement_transfers
     order by created_at desc limit ${limit}
  `
  return rows.map(toTransfer)
}

/** Spend per service, summed in the database in exact integer arithmetic. */
export async function transferTotals(sql: Db | Tx): Promise<Readonly<Record<string, string>>> {
  const rows = await sql<{ service: string; total: string }[]>`
    select service, coalesce(sum(amount_wei), 0)::text as total
      from engagement_transfers where state = 'posted'
     group by service
  `
  return Object.fromEntries(rows.map((r) => [r.service, r.total]))
}

/**
 * A positive amount of EMBER wei from a decimal string. Never a JSON number near money.
 *
 * 78 digits, not the 19 this allowed while the column was a bigint of Shards. That is not a
 * loosened guard, it is the same guard against the widened column: `numeric(78,0)` holds any
 * uint256, and at 18 decimals every transfer worth approving is already past
 * `Number.MAX_SAFE_INTEGER` — so a JSON number here would not merely risk the low bits, it would
 * routinely lose them. The ceiling is what bounds the value; the length only bounds the parse.
 */
export function parseTransferWei(value: string): bigint {
  if (!/^[0-9]{1,78}$/.test(value)) {
    throw new EngagementError(
      'an amount is a positive decimal string of EMBER wei, not a number',
    )
  }
  const amount = BigInt(value)
  if (amount <= 0n) throw new EngagementError('an amount must be at least one wei')
  return amount
}

/** A cap, which unlike a transfer may legitimately be zero — zero is "nothing may move". */
export function parseCapWei(value: string): bigint {
  if (!/^[0-9]{1,78}$/.test(value)) {
    throw new EngagementError('a cap is a decimal string of EMBER wei, not a number')
  }
  return BigInt(value)
}

/** A wei amount from a decimal string. numeric(78,0) holds any uint256; so does this. */
export function parseWei(value: string): bigint {
  if (!/^[0-9]{1,78}$/.test(value)) {
    throw new EngagementError('a wei amount is a positive decimal string, not a number')
  }
  return BigInt(value)
}
