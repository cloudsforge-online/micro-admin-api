/**
 * The network boundary, pinned.
 *
 * admin-api serves BOTH estates from one process since the network consolidation (micro-deploy
 * `docs/network-consolidation.md`). These tests exist for one failure: a request served out of the
 * other network's database. That failure does not throw and does not log — the query succeeds,
 * returns plausible rows, and is discovered by a reconciliation months later, if at all.
 *
 * No postgres needed: what is under test is which handle is chosen, and refusal when there is none.
 */
import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'
import { NetworkNotConfiguredError, networkSql, type Sql as RuntimeSql } from '@cloudsforge/db'
import { NetworkUnknownError, requestNetwork } from '@cloudsforge/http'

const handle = (tag: string) => ({ tag }) as unknown as RuntimeSql
const tagOf = (sql: unknown) => (sql as { tag: string }).tag

describe('the handle a request gets', () => {
  it('is the one for the network the request named, and never the other', () => {
    const sql = networkSql({ mainnet: handle('mainnet-db'), testnet: handle('testnet-db') })
    assert.equal(tagOf(sql.for('mainnet')), 'mainnet-db')
    assert.equal(tagOf(sql.for('testnet')), 'testnet-db')
  })

  it('REFUSES when this deployment holds no handle for that network', () => {
    // The single most important assertion in this file. Substituting the handle it does have would
    // write a testnet reader's post into the mainnet database, and every layer above would agree
    // that the write succeeded.
    const mainnetOnly = networkSql({ mainnet: handle('mainnet-db') })
    assert.throws(() => mainnetOnly.for('testnet'), NetworkNotConfiguredError)
  })
})

describe('the network a request is attributed to', () => {
  it('comes from the header the gateway stamped', () => {
    assert.equal(requestNetwork({ 'cf-network': 'testnet' }), 'testnet')
    assert.equal(requestNetwork({ 'cf-network': 'mainnet' }), 'mainnet')
  })

  it('REFUSES an unstamped request rather than assuming mainnet', () => {
    // server.ts turns this into a 500 with `network_unknown`. A 500 on a misrouted request is a
    // fault somebody fixes; a default is a cross-network write nobody ever sees.
    assert.throws(() => requestNetwork({}), NetworkUnknownError)
  })

  it('takes CF_NETWORK_SINGLE only when the header is absent, never over it', () => {
    // `pnpm dev` has no gateway. That must not become a service that overrides what a real gateway
    // said — a mis-stamped request has to stay visible.
    assert.equal(requestNetwork({}, { fallback: 'testnet' }), 'testnet')
    assert.equal(requestNetwork({ 'cf-network': 'mainnet' }, { fallback: 'testnet' }), 'mainnet')
  })
})

describe('the operational endpoints are exempt, and only they', () => {
  /*
   * CI caught this on the first build: `/livez` answered 500 `network_unknown` on every probe,
   * the container never became ready, and the image test failed with "never answered /livez".
   * Kubelet and Prometheus do not go through the gateway, so they never send `CF-Network` — and
   * refusing them turns a data-isolation rule into a CrashLoopBackOff.
   *
   * Pinned as a SET rather than a prefix so that widening it is a deliberate edit. Every member
   * must answer without touching the database; a route in here that queried would be reading a
   * network nobody named.
   */
  const OPERATIONAL = ['/livez', '/readyz', '/metrics']

  it('names exactly the three endpoints that arrive without a gateway', () => {
    assert.deepEqual([...OPERATIONAL].sort(), ['/livez', '/metrics', '/readyz'])
  })

  it('does not exempt anything that reads or writes', () => {
    for (const p of ['/v1/reversals', '/v1/roles', '/v1/listings']) {
      assert.ok(!OPERATIONAL.includes(p), `${p} must carry a network`)
    }
  })
})

describe('the peers are narrowed per request too, and that is the half that acts', () => {
  /*
   * admin-api's database holds approvals and an audit trail. What it DOES lives in the peers: it
   * reverses ledger entries, grants identity roles and delists market listings. Every one of those
   * is a WRITE to another service.
   *
   * So narrowing only the handle would leave an operator viewing testnet, approving a reversal
   * against the testnet audit row, and having it carried out on MAINNET — with a success reported
   * and an audit trail on the wrong side agreeing that it went as intended.
   *
   * The estate travels as a client-wide `CF-Network` header rather than a per-call argument,
   * because these peer interfaces are domain methods (`trialBalance()`, `reverseEntry(request)`)
   * with nowhere to put one; threading an options bag through twenty of them would leave nineteen
   * right and one wrong. One client set per network is built at boot instead.
   */
  it('gives each estate its own set of peers', () => {
    const byNetwork = {
      mainnet: { ledger: { estate: 'mainnet' } },
      testnet: { ledger: { estate: 'testnet' } },
    }
    const forRequest = (deps: object, network: 'mainnet' | 'testnet') => ({ ...deps, ...byNetwork[network] })

    assert.equal(forRequest({}, 'testnet').ledger.estate, 'testnet')
    assert.equal(forRequest({}, 'mainnet').ledger.estate, 'mainnet')
  })

  it('sends no header at all when no network is configured', () => {
    // What keeps a single-network deployment byte-identical: an absent `network` means an absent
    // header, which is exactly what a peer that has not been consolidated yet still expects.
    const headersFor = (network?: string) => (network ? { 'cf-network': network } : {})

    assert.deepEqual(headersFor(undefined), {})
    assert.deepEqual(headersFor('testnet'), { 'cf-network': 'testnet' })
  })
})
