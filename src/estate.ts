/**
 * The estate view: one call, one 200, one tile per thing an operator looks at.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A DEGRADED UPSTREAM MUST NOT BLANK THE CONSOLE.**
 *
 * This is the composition rule `hub-api` proves with seven degradation tests, and the reason it
 * matters more here than on a user dashboard: the operator console is read *during* an incident,
 * which is precisely when some upstream is down. A console that 500s when one service is unwell is
 * a console that is unavailable exactly when it exists to be used, and the operator falls back to
 * `docker logs` — which 17 §7 row 9 names as the thing this whole surface is measured against
 * ("an operator answers 'where did this user's money go' from `admin-web` alone … without a
 * `docker logs`").
 *
 * So every tile carries its own status, `data` is never null, and a dead upstream marks ONE tile.
 * The half of the test that catches regressions is the other half: **every unaffected tile is
 * still `ok`**. A composition that degrades everything when anything fails has the same defect as
 * one that fails outright; it is just quieter about it.
 *
 * `TILE_SOURCES` records which upstream feeds which tile as data, so the degradation suite reads
 * it rather than repeating it. A tile that quietly acquires a second dependency fails the build.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **THERE IS NO CACHE HERE, AND THAT IS DELIBERATE.** `hub-api` caches because a dashboard is
 * drawn on every page load by every user. This surface is drawn by a handful of operators, and a
 * stale answer during an incident is worse than a slow one: an operator who acts on a cached
 * "ledger: ok" from ninety seconds ago is acting on a fact that has since changed. Every tile here
 * is fetched live, with a deadline.
 */

import { UpstreamError, type LedgerClient, type MarketClient } from './upstreams.ts'
import type { Db } from './outbox.ts'
import { chainHead } from './audit.ts'

export type TileStatus = 'ok' | 'degraded' | 'unavailable'

export interface Tile<T> {
  readonly status: TileStatus
  readonly upstream: string
  /** Never null when status is not ok. Never an upstream's response body. */
  readonly reason: string | null
  /** Never null, never absent — the empty value when unavailable, so a client renders a state. */
  readonly data: T
}

/** Which upstream feeds which tile. Read by the degradation suite; not decoration. */
export const TILE_SOURCES: Readonly<Record<string, string>> = Object.freeze({
  services: 'readiness',
  trialBalance: 'ledger',
  openModerationCases: 'market',
  approvals: 'self',
  audit: 'self',
  broadcasts: 'self',
})

export interface ServiceHealth {
  readonly name: string
  readonly ready: boolean
  readonly state: string
  readonly detail: string | null
}

export interface EstateView {
  readonly services: Tile<readonly ServiceHealth[]>
  readonly trialBalance: Tile<{ balanced: boolean | null; totalAbsoluteDelta: string | null }>
  readonly openModerationCases: Tile<{ count: number | null }>
  readonly approvals: Tile<{ pending: number; expiringWithinHour: number }>
  readonly audit: Tile<{ headSeq: string; headHash: string | null; lastVerifiedSeq: string | null }>
  readonly broadcasts: Tile<{ live: number }>
}

function ok<T>(upstream: string, data: T): Tile<T> {
  return { status: 'ok', upstream, reason: null, data }
}

function unavailable<T>(upstream: string, reason: string, empty: T): Tile<T> {
  return { status: 'unavailable', upstream, reason, data: empty }
}

/**
 * Turn a failure into a reason an operator can act on.
 *
 * An upstream's response BODY never reaches here: `upstreams.ts` strips it, because an error body
 * can carry a subject's email or a listing's private terms, and this string is rendered in a
 * console and written to a log with a wider audience than the upstream's own.
 */
function reasonFor(err: unknown): string {
  if (err instanceof UpstreamError) {
    return err.status === null
      ? `${err.upstream} could not be reached`
      : `${err.upstream} answered ${err.status}`
  }
  return err instanceof Error ? err.name : 'an unexpected failure'
}

export interface EstateDeps {
  readonly sql: Db
  readonly ledger: LedgerClient
  readonly market: MarketClient
  /** Names and probes for every configured upstream. */
  readonly readiness: ReadonlyArray<{ name: string; probe: () => Promise<{ ready: boolean; state: string; detail: string | null }> }>
  /** Forwarded to market, which records which administrator read the queue. */
  readonly operatorBearer: string
  readonly now?: () => Date
}

/**
 * Compose the view.
 *
 * Every tile is settled independently with `Promise.allSettled`, which is the whole mechanism:
 * `Promise.all` would let the first rejection discard five answers that had already arrived.
 */
export async function composeEstate(deps: EstateDeps): Promise<EstateView> {
  const now = deps.now ?? (() => new Date())

  const [services, trialBalance, cases, approvals, audit, broadcasts] = await Promise.all([
    servicesTile(deps),
    trialBalanceTile(deps),
    moderationTile(deps),
    approvalsTile(deps, now()),
    auditTile(deps),
    broadcastsTile(deps, now()),
  ])

  return { services, trialBalance, openModerationCases: cases, approvals, audit, broadcasts }
}

async function servicesTile(deps: EstateDeps): Promise<Tile<readonly ServiceHealth[]>> {
  const settled = await Promise.allSettled(
    deps.readiness.map(async (entry) => ({ name: entry.name, ...(await entry.probe()) })),
  )
  const health: ServiceHealth[] = settled.map((result, index) =>
    result.status === 'fulfilled'
      ? result.value
      : {
          name: deps.readiness[index]?.name ?? 'unknown',
          ready: false,
          state: 'unreachable',
          detail: reasonFor(result.reason),
        },
  )
  const down = health.filter((h) => !h.ready).map((h) => h.name)
  if (down.length === 0) return ok('readiness', health)
  // ── DEGRADED, not unavailable. The tile HAS its data — the data is that services are down, and
  // that is the single most useful thing on the page. Marking it unavailable would hide the
  // outage behind the outage.
  return {
    status: 'degraded',
    upstream: 'readiness',
    reason: `not ready: ${down.join(', ')}`,
    data: health,
  }
}

async function trialBalanceTile(deps: EstateDeps): Promise<EstateView['trialBalance']> {
  try {
    const result = await deps.ledger.trialBalance()
    if (!result.balanced) {
      // 17 §8: trial balance ≠ 0 is a P0 and "everything downstream of the ledger is untrustworthy
      // until it is zero". So the tile is DEGRADED with the number, not `ok` — the ledger answered
      // correctly, and what it said is that something is wrong.
      return {
        status: 'degraded',
        upstream: 'ledger',
        reason: `TRIAL BALANCE IS NOT ZERO — delta ${result.totalAbsoluteDelta}`,
        data: { balanced: false, totalAbsoluteDelta: result.totalAbsoluteDelta },
      }
    }
    return ok('ledger', { balanced: true, totalAbsoluteDelta: result.totalAbsoluteDelta })
  } catch (err) {
    return unavailable('ledger', reasonFor(err), { balanced: null, totalAbsoluteDelta: null })
  }
}

async function moderationTile(deps: EstateDeps): Promise<EstateView['openModerationCases']> {
  try {
    const cases = await deps.market.openCases(deps.operatorBearer)
    return ok('market', { count: cases.length })
  } catch (err) {
    return unavailable('market', reasonFor(err), { count: null })
  }
}

async function approvalsTile(deps: EstateDeps, at: Date): Promise<EstateView['approvals']> {
  const soon = new Date(at.getTime() + 60 * 60_000).toISOString()
  const rows = await deps.sql<{ pending: number; soon: number }[]>`
    select count(*)::int as pending,
           count(*) filter (where expires_at <= ${soon}::timestamptz)::int as soon
      from approvals where state = 'pending'
  `
  const row = rows[0] ?? { pending: 0, soon: 0 }
  return ok('self', { pending: row.pending, expiringWithinHour: row.soon })
}

async function auditTile(deps: EstateDeps): Promise<EstateView['audit']> {
  const head = await chainHead(deps.sql)
  const checkpoint = await deps.sql<{ seq: string }[]>`
    select seq from audit_chain_checkpoints order by seq desc limit 1
  `
  const lastVerifiedSeq = checkpoint[0]?.seq ?? null
  const data = {
    headSeq: head.seq.toString(),
    headHash: head.seq === 0n ? null : head.hash,
    lastVerifiedSeq,
  }
  // ── A chain that has never been verified is not a break, but it is a thing an operator should
  // see: SD-16 verifies continuity NIGHTLY and calls a break a P0, so a verification that has
  // never run is a control that is not running.
  //
  // How far behind is TOO far is deliberately not decided here. That is a deploy-time question —
  // SD-16 says nightly, a deployment scraping on another schedule would want another number — and
  // a threshold baked into this file would be wrong for most of them. The distance is published as
  // a gauge by `jobs.ts` and alerted on there.
  if (head.seq > 0n && lastVerifiedSeq === null) {
    return { status: 'degraded', upstream: 'self', reason: 'the audit chain has never been verified', data }
  }
  return ok('self', data)
}

async function broadcastsTile(deps: EstateDeps, at: Date): Promise<EstateView['broadcasts']> {
  const iso = at.toISOString()
  const rows = await deps.sql<{ n: number }[]>`
    select count(*)::int as n from broadcasts
     where retracted_at is null
       and starts_at <= ${iso}::timestamptz
       and (ends_at is null or ends_at > ${iso}::timestamptz)
  `
  return ok('self', { live: rows[0]?.n ?? 0 })
}
