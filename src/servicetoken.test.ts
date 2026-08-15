/**
 * **THE PRIVILEGED SURFACE AND THE TEN-MINUTE TOKEN, DRIVEN PAST THE EXPIRY.**
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * ## The defect, as measured rather than as reasoned about
 *
 * `ADMIN_API_SERVICE_TOKEN` held a token that lives **600 seconds** (`identity/src/tokens.ts`).
 * The composition root read it once, at import — `const serviceToken = () => env.serviceToken`,
 * `index.ts` — and handed that to the ledger, market, billing and identity clients. Measured on
 * the live estate on 2026-08-05, the value inside the container was a 701-byte JWT that had been
 * **expired for 26 hours**, on a container reporting healthy the entire time.
 *
 * `/livez` never noticed, and could not have: it makes no outbound call, so the healthcheck never
 * exercises the credential. The first thing that fails is an operator approving a ledger reversal
 * at two in the morning.
 *
 * ## Why a longer expiry is not the fix
 *
 * `settlement/src/index.ts` read a 600-second token once at boot. Identity had issued it exactly
 * one token, ever — so settlement authenticated for ten minutes after each restart and was dead
 * thereafter, producing **1,315 undelivered withdrawal attempts** and a treasury that read as
 * empty. One 401 presented as two apparently unrelated incidents. A longer-lived JWT moves that
 * cliff; it does not remove it. Exchange-and-refresh removes it, and the 600 seconds stays
 * unchanged on purpose — rotation IS expiry (SD-12).
 *
 * ## Why every other test in this repository is blind to it
 *
 * `upstreams.test.ts` is 311 lines against a real HTTP socket and it is green in both the working
 * and the broken world, because every case in it calls `config()` and supplies its own bearer. **A
 * test that mints a token and immediately uses it proves nothing about this defect** — the token is
 * never asked to survive its own lifetime, and at the speed of a test a hard-coded string and a
 * live credential are indistinguishable. That is exactly the property this file removes: below, the
 * clock moves **ELEVEN MINUTES** past a token the process already holds, that token is shown to be
 * refused **by a real `Verifier`**, and only then is the privileged action attempted again.
 *
 * ## The assertion that stops this file being green for the wrong reason
 *
 * `authorizedFetch` re-mints and replays once on a 401. So a completely broken refresh SCHEDULE
 * would still end in a successful reversal — one 401, one re-mint, one replay — and a test that
 * only checked the outcome would pass straight over it. The post-expiry case therefore asserts
 * **zero 401s**: the token must have been refreshed BEFORE it was ever presented. The replay path
 * is the backstop, not the mechanism.
 *
 * ## Going through `buildUpstreams` is the whole point
 *
 * A test that constructs its own `ServiceTokenProvider` and its own `httpLedgerClient` proves the
 * provider works, which is `@cloudsforge/auth`'s job. It proves nothing about whether THIS SERVICE
 * uses it, and "this service does not use it" was the defect. Reverting `upstreams.ts` to
 * `serviceToken: () => env.serviceToken` turns the cases below red — and `BASELINE` models that
 * exact old seam, against the same fixtures, so this file also demonstrates the failure it fixes.
 *
 * ## What is real here, and what is not
 *
 *   * **Real**: `buildUpstreams` (the wiring under test), `ServiceTokenProvider`, `HttpClient`,
 *     `httpLedgerClient`, `httpIdentityClient`, a real `Verifier` and jose's own expiry arithmetic.
 *   * **Simulated**: the clock, and the peers' transports. `mock.timers` moves `Date` only, so jose
 *     decides expiry from the same instant the provider schedules against — nothing here decides
 *     expiry by hand, which is how a test ends up agreeing with the code it is checking.
 *
 * No database. Nothing here touches a table, so it runs wherever `node --test` does.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test, mock, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, generateKeyPair } from 'jose'
import { AUDIENCE, ServiceTokenUnavailableError, Verifier } from '@cloudsforge/auth'
import { buildUpstreams, UpstreamError, type UpstreamEnv } from './upstreams.ts'

const ISSUER = 'https://identity.test'
const IDENTITY = 'http://identity:4001'
const LEDGER = 'http://ledger:4007'
const MARKET = 'http://market:4013'
const BILLING = 'http://billing:4009'

/**
 * Fabricated: identity's shape, none of its entropy, and **never a value out of `tokens.env`**.
 *
 * THE HYPHEN IS DELIBERATE and is the most important character in this file. A credential body is
 * base64**url**, so `-` and `_` are in its alphabet. Measured on the running estates, the mainnet
 * credential is alphanumeric and the testnet one CONTAINS A HYPHEN — so a guard written to the
 * mainnet value, or a fixture without one, reads as obviously right, passes mainnet and kills
 * testnet at boot. Keeping the hyphen here means that mistake fails CI rather than one estate.
 */
const CREDENTIAL = 'cfsc_0000000000000000000000000000000000-000test'

/** identity/src/tokens.ts. Unchanged by this fix, and it must stay unchanged. */
const SERVICE_TTL_SECONDS = 600

/** What this service actually demands of its own bearer — `upstreams.ts`'s cited route guards. */
const SCOPES = ['ledger:post', 'ledger:read', 'identity:admin'] as const

/** Well in the past, and fixed, so nothing here depends on the day it is run. */
const T0 = Date.UTC(2024, 0, 1, 0, 0, 0)

/** Move the whole world — the provider's schedule and jose's expiry check — to `T0 + ms`. */
function clockAt(ms: number): void {
  mock.timers.reset()
  mock.timers.enable({ apis: ['Date'], now: new Date(T0 + ms) })
}

afterEach(() => mock.timers.reset())

const OPERATOR = 'user:11111111-1111-4111-8111-111111111111'
const CORRELATION = '22222222-2222-4222-8222-222222222222'
const APPROVAL = '33333333-3333-4333-8333-333333333333'

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * A REAL IDENTITY AND A REAL LEDGER, in the sense that matters.
 *
 * Identity signs RS256 tokens with a 600-second expiry against the simulated clock. The peers hand
 * whatever they are given to a real `Verifier`, check the scope the route's cited guard demands off
 * the verified principal, and answer 401 when jose says the token is bad — which is what the live
 * estate's ledger did for 26 hours. Nothing decides expiry by hand.
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

type Peer = 'ledger' | 'market' | 'billing' | 'identity'

interface Call {
  readonly peer: Peer
  readonly token: string | null
  readonly status: number
}

interface World {
  readonly fetch: typeof globalThis.fetch
  exchanges: number
  calls: Call[]
  consecutive401: number
  /** A pre-minted token valid at `T0` that cannot be renewed. The defect's input. */
  readonly staticToken: string
  /**
   * Refuse the next bearer once, whatever it is, then behave normally.
   *
   * The case the SCHEDULE cannot cover and `authorizedFetch` exists for: a token this process
   * believes is fresh which the ledger rejects anyway — clock skew between the two, a credential
   * revoked mid-flight, a process paused between reading the token and sending it.
   */
  refuseNextBearer: boolean
}

function peerOf(url: string): Peer {
  if (url.startsWith(LEDGER)) return 'ledger'
  if (url.startsWith(MARKET)) return 'market'
  if (url.startsWith(BILLING)) return 'billing'
  return 'identity'
}

/** The scope each peer's cited guard demands. `upstreams.ts`'s header names all four. */
const NEEDS: Record<Peer, string> = {
  ledger: 'ledger:post',
  market: 'market:admin',
  billing: 'billing:grant',
  identity: 'identity:admin',
}

async function world(): Promise<World> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const keySet = (async () => publicKey) as never
  const verifier = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })

  // RS256 is deterministic, so two tokens signed from the same payload at the same simulated
  // instant are the same string. Identity mints a uuidv7 jti per token; the counter restores that,
  // and without it "the service minted a genuinely new token" could not be asserted at all.
  let jti = 0
  const mint = (issuedAtMs: number): Promise<string> =>
    new SignJWT({ typ: 'service', scopes: [...SCOPES], jti: `t-${++jti}` })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuedAt(Math.floor(issuedAtMs / 1000))
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('service:admin-api')
      .setExpirationTime(Math.floor(issuedAtMs / 1000) + SERVICE_TTL_SECONDS)
      .sign(privateKey)

  const staticToken = await mint(T0)

  const self: World = {
    exchanges: 0,
    calls: [],
    consecutive401: 0,
    staticToken,
    refuseNextBearer: false,

    fetch: (async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url

      // The exchange. `identity` serves both this and `PUT /internal/users/:id/roles`, so the PATH
      // decides — which is also a check that the provider posts where it says it does.
      if (url === `${IDENTITY}/service-tokens/exchange`) {
        if (new Headers(init?.headers).get('authorization') !== `Bearer ${CREDENTIAL}`) {
          return new Response('{"error":"unauthenticated"}', { status: 401 })
        }
        self.exchanges += 1
        return new Response(
          JSON.stringify({
            token: await mint(Date.now()),
            service: 'admin-api',
            scopes: [...SCOPES],
            expiresIn: SERVICE_TTL_SECONDS,
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        )
      }

      const peer = peerOf(url)

      // The loop guard counts CONSECUTIVE refusals rather than total calls, because
      // `authorizedFetch` re-mints and replays exactly once on a 401 — a fault would show as an
      // unbroken run of them, while a cap on the total would be a cap on how many operator actions
      // a test may drive, which is the wrong quantity entirely.
      if (self.consecutive401 > 4) throw new Error('the 401 replay is looping')

      const presented =
        new Headers(init?.headers).get('authorization')?.replace(/^Bearer /, '') ?? null
      const refuse = (status: number): Response => {
        self.consecutive401 += 1
        self.calls.push({ peer, token: presented, status })
        return new Response(
          '{"error":{"code":"unauthenticated","message":"a valid bearer token is required"}}',
          { status },
        )
      }

      if (presented === null) return refuse(401)
      if (self.refuseNextBearer) {
        self.refuseNextBearer = false
        return refuse(401)
      }

      // ── MARKET AND BILLING TAKE THE OPERATOR'S OWN BEARER, AND THAT MUST SURVIVE THIS FIX ────
      // SD-11: the upstream's audit names the HUMAN. A refactor that routed every call through the
      // service bearer would be invisible in every outcome and would quietly erase which
      // administrator resolved a case. So those two accept an opaque operator bearer and reject a
      // service token, which is the assertion in reverse.
      if (peer === 'market' || peer === 'billing') {
        if (presented.startsWith('ey')) return refuse(403)
        self.consecutive401 = 0
        self.calls.push({ peer, token: presented, status: 200 })
        return new Response(
          peer === 'market'
            ? JSON.stringify({ case: { id: 'case-1', state: 'upheld' } })
            : JSON.stringify({ alreadyRevoked: false, reversalEntryId: 'entry-7' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        )
      }

      try {
        const principal = await verifier.principal(presented)
        if (principal.kind !== 'service' || !principal.scopes.includes(NEEDS[peer])) {
          return refuse(403)
        }
      } catch {
        // jose refused it: expired, or not signed by this key. THE CLIFF, seen from the ledger's
        // side, and the exact 401 measured on the live estate.
        return refuse(401)
      }

      self.consecutive401 = 0
      self.calls.push({ peer, token: presented, status: 200 })
      return new Response(
        peer === 'ledger'
          ? JSON.stringify({ entry: { id: 'entry-9', reversesEntryId: 'entry-1' }, replayed: false })
          : JSON.stringify({ roles: ['admin'], granted: ['admin'], revoked: [] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }) as typeof globalThis.fetch,
  }
  return self
}

/**
 * **`buildUpstreams`, not a hand-rolled client.** See the header: this is what makes the file a
 * test of THIS SERVICE'S wiring rather than of `@cloudsforge/auth`.
 */
function upstreamsFor(w: World, credential: string | null, staticToken: string | null) {
  const env: UpstreamEnv = {
    identityUrl: IDENTITY,
    identityCredential: credential,
    serviceToken: staticToken,
    ledgerUrl: LEDGER,
    notifyUrl: 'http://notify.test',
    marketUrl: MARKET,
    billingUrl: BILLING,
    ndaUrl: 'http://nda.test',
    upstreamDeadlineMs: 4_000,
  }
  return buildUpstreams(env, { fetch: w.fetch })
}

const reversal = {
  entryId: 'entry-1',
  idempotencyKey: 'admin-api:approval:abc',
  description: 'reversing a duplicated sweep',
  correlationId: CORRELATION,
  operator: OPERATOR,
  approvalId: APPROVAL,
} as const

const count401 = (w: World): number => w.calls.filter((call) => call.status === 401).length
const ledgerCalls = (w: World): Call[] => w.calls.filter((call) => call.peer === 'ledger')

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE CASES
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

test('the credential is EXCHANGED, and it is never presented to a peer as a bearer', async () => {
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  assert.equal(upstreams.mode, 'exchanged', 'buildUpstreams did not choose the credential')
  assert.equal(w.exchanges, 0, 'the provider exchanged before anything needed a token')

  const entry = await upstreams.ledger.reverseEntry(reversal)

  assert.equal(entry.id, 'entry-9')
  assert.equal(w.exchanges, 1, 'the credential was not exchanged for a token')
  assert.deepEqual(ledgerCalls(w).map((c) => c.status), [200])
  // ── THE VERBATIM-PRESENTATION ASSERTION, which is half of micro-org #222 ──────────────────────
  // Wiring the boot guard in without this would pass the check and then 401 every upstream call:
  // a loud failure traded for a silent one. The credential is worth nothing to a peer — it is not
  // a JWT, `Verifier` cannot parse it, and every ledger call carrying it answers 401.
  assert.notEqual(ledgerCalls(w)[0]?.token, CREDENTIAL, 'the CREDENTIAL was presented as a bearer')
  assert.ok(ledgerCalls(w)[0]?.token?.startsWith('ey'), 'what was presented is not a JWT')
})

test('THE PROPERTY: eleven minutes on, an approved reversal still posts — and it costs no 401', async () => {
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  await upstreams.ledger.reverseEntry(reversal)
  const bootToken = ledgerCalls(w)[0]?.token
  assert.ok(bootToken)
  assert.equal(w.exchanges, 1)

  // ── ELEVEN MINUTES. The token this process minted at boot is now dead. ───────────────────────
  clockAt(11 * 60 * 1_000)

  // Proved against a REAL `Verifier` and jose's own arithmetic rather than asserted. If this line
  // ever stops throwing, the rest of this test is meaningless and it should fail here.
  await assert.rejects(
    (async () => {
      const response = await w.fetch(`${LEDGER}/trial-balance`, {
        headers: { authorization: `Bearer ${bootToken}` },
      })
      if (!response.ok) throw new Error(`the ledger refused the boot token: ${response.status}`)
    })(),
    /the ledger refused the boot token: 401/,
    'the boot token outlived 600 seconds; the cliff is not being modelled',
  )

  const before401s = count401(w)
  const beforeCalls = w.calls.length

  // The reversal an operator approves eleven minutes after a deploy. Under the old seam this is
  // where the ledger starts 401ing for ever and the console reports the LEDGER as unwell.
  const entry = await upstreams.ledger.reverseEntry(reversal)

  const after = w.calls.slice(beforeCalls)
  assert.equal(entry.id, 'entry-9')
  assert.deepEqual(after.map((c) => c.status), [200], 'the post-expiry reversal was refused')
  assert.notEqual(after[0]?.token, bootToken, 'the DEAD boot token was presented again')
  assert.equal(w.exchanges, 2, 'the provider did not re-mint on schedule')

  // ── THE ASSERTION THAT STOPS THIS BEING GREEN FOR THE WRONG REASON ──────────────────────────
  // `authorizedFetch` would have rescued a totally broken schedule with one 401 + re-mint + replay
  // and the reversal would still have posted. Zero 401s means the token was refreshed BEFORE it
  // was presented, which is the guarantee. The replay path is the backstop, not the mechanism.
  assert.equal(
    count401(w),
    before401s,
    'the post-expiry call cost a 401 — the refresh SCHEDULE is broken and the replay path hid it',
  )
})

/** Let a fire-and-forget background exchange settle. `mock.timers` moves `Date` only, so the real
 *  microtask and immediate queues still drain. */
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve))
}

test('THE REFRESH IS PROACTIVE: a token still valid but past 80% is replaced BEHIND the request', async () => {
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  // **THE CASE THAT ZERO-401 CANNOT MAKE ON ITS OWN, AND THE REASON IT IS HERE.**
  //
  // Mutating `refreshAt` to 0.999 — a schedule that effectively never fires — leaves every other
  // case in this file green. It has to: the provider still knows its own expiry, so at minute
  // eleven it BLOCKS, exchanges in front of the request, and no 401 is ever seen. Correct, and not
  // the guarantee. The guarantee is the 20% slack: the refresh happens while the held token is
  // STILL GOOD, so a failing identity can be retried for two minutes without a single request
  // waiting on it or seeing an expired credential.
  //
  // So this drives a call at NINE minutes — past the jittered 80% refresh point (which lands
  // between 480s and 510s), and comfortably inside the token's 600-second life — and asserts a
  // second exchange happened anyway. Under a broken schedule the count stays at 1.
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  await upstreams.ledger.reverseEntry(reversal)
  const bootToken = ledgerCalls(w)[0]?.token
  assert.equal(w.exchanges, 1)

  clockAt(9 * 60 * 1_000)
  await upstreams.ledger.reverseEntry(reversal)

  // The token presented was the one already held: the refresh runs BEHIND the request, so the
  // caller pays nothing for it. That is the other half of the property.
  assert.equal(ledgerCalls(w)[1]?.token, bootToken, 'the caller waited on a refresh it did not need')

  await settle()
  assert.equal(
    w.exchanges,
    2,
    'no background exchange at 90% of the token’s life — the refresh SCHEDULE never fires, and the ' +
      '20% slack that lets a failing identity be retried without any request noticing is gone',
  )
  assert.equal(count401(w), 0)
})

test('EIGHT HOURS of operator actions, and not one 401', async () => {
  // Thirty-two approved reversals over a whole shift, each step crossing more than one token
  // lifetime. Actions a minute apart would never test anything the first case does not.
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  const RUNS = 32
  const STEP_MS = (8 * 60 * 60 * 1_000) / RUNS
  assert.ok(
    STEP_MS > SERVICE_TTL_SECONDS * 1_000,
    'the step is shorter than a token lifetime, so this proves nothing the minute-zero case does not',
  )

  for (let run = 0; run < RUNS; run += 1) {
    clockAt(run * STEP_MS)
    const entry = await upstreams.ledger.reverseEntry(reversal)
    assert.equal(entry.id, 'entry-9', `the reversal at hour ${(run * STEP_MS) / 3_600_000} was refused`)
  }

  assert.equal(w.calls.length, RUNS, 'a reversal made more than one ledger call')
  assert.deepEqual([...new Set(w.calls.map((c) => c.status))], [200])
  // One exchange per action, because each step is longer than a token's whole life. The point is
  // that it kept up, not the exact count — but a count of 1 would mean the schedule never fired.
  assert.ok(w.exchanges >= RUNS - 1, `the provider exchanged only ${w.exchanges} times across ${RUNS} actions`)
  // Distinct bearers, so "it re-minted" is a fact about the wire rather than about a counter.
  assert.ok(
    new Set(w.calls.map((c) => c.token)).size >= RUNS - 1,
    'the same token was reused past its life',
  )
})

test('BASELINE: the seam this replaced leaves every privileged action dead from minute ten', async () => {
  clockAt(0)
  const w = await world()
  // `identityCredential: null`, `serviceToken: <a real 600s JWT>` — i.e. exactly what
  // `const serviceToken = () => env.serviceToken` did, and exactly what the estate runs today.
  const upstreams = upstreamsFor(w, null, w.staticToken)
  assert.equal(upstreams.mode, 'static', 'the baseline is not modelling the pre-minted token')

  const atBoot = await upstreams.ledger.reverseEntry(reversal)
  assert.equal(atBoot.id, 'entry-9', 'the baseline failed at minute zero')

  clockAt(11 * 60 * 1_000)

  // **This is the 401 measured on the live estate, reproduced.** `UpstreamError` carries
  // `status: 401` and `peerDecided: true`, so the operator console renders "the ledger refused
  // admin-api" — when the truth is that this container's own credential died 26 hours ago.
  await assert.rejects(
    async () => upstreams.ledger.reverseEntry(reversal),
    (err: unknown) => err instanceof UpstreamError && err.status === 401 && err.upstream === 'ledger',
    'the pre-minted token survived its own 600-second life; the baseline is not the old seam',
  )
  assert.equal(w.exchanges, 0, 'the baseline exchanged something; it is not the old seam')
})

test('THE PRECEDENCE: with BOTH set, the credential wins and the dead token is never presented', async () => {
  // **This is the state the estate will actually be in**: `ADMIN_API_SERVICE_TOKEN` is set today
  // and stays set while the credential is added. If the pre-minted token won, the deploy would look
  // correct, the boot log would say `exchanged`, and the cliff would still be there. No other case
  // in this file can see that, because each sets exactly one of the two.
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, w.staticToken)
  assert.equal(upstreams.mode, 'exchanged', 'the pre-minted token beat the credential')

  await upstreams.ledger.reverseEntry(reversal)
  assert.equal(w.exchanges, 1, 'the credential was not exchanged; the static token was used instead')
  assert.notEqual(w.calls[0]?.token, w.staticToken, 'the un-renewable token was presented')

  // Eleven minutes on, the static token is dead. If it had won at minute zero this would 401.
  clockAt(11 * 60 * 1_000)
  const entry = await upstreams.ledger.reverseEntry(reversal)
  assert.equal(entry.id, 'entry-9')
  assert.equal(w.exchanges, 2)
  assert.equal(count401(w), 0)
})

test('THE BACKSTOP: a bearer this process believes is fresh, refused anyway, is re-minted and replayed once', async () => {
  // The case the SCHEDULE cannot cover: the refresh point is computed from this process's clock and
  // `expiresIn`, the ledger decides from `exp` and ITS clock, and nothing makes those agree. A
  // credential revoked mid-flight looks identical.
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  w.refuseNextBearer = true
  const entry = await upstreams.ledger.reverseEntry(reversal)

  assert.equal(entry.id, 'entry-9')
  assert.deepEqual(
    w.calls.map((c) => c.status),
    [401, 200],
    'the 401 was not replayed — `authorizedFetch` is not wired into the clients',
  )
  assert.notEqual(w.calls[1]?.token, w.calls[0]?.token, 'the REJECTED token was replayed unchanged')
  assert.equal(w.exchanges, 2, 'the rejected token was not discarded and re-minted')
})

test('IDENTITY IS ON THE SAME CREDENTIAL — the wiring is not ledger-only', async () => {
  // `buildUpstreams` hands one `serviceToken` and one `fetch` to all four clients, and this says so
  // about the most consequential of them. `PUT /internal/users/:id/roles` is gated on
  // `authenticateIdentityAdmin` (identity/src/server.ts), which requires a SERVICE token with
  // `identity:admin` and refuses an operator token outright — so there is no fallback path here at
  // all: a dead credential means no operator can be promoted or demoted, ever.
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  clockAt(11 * 60 * 1_000)
  const change = await upstreams.identity.setRoles({
    userId: '44444444-4444-4444-8444-444444444444',
    roles: ['admin'],
    actor: OPERATOR,
    reason: 'approved promotion',
    approvalId: APPROVAL,
    correlationId: CORRELATION,
  })

  assert.deepEqual(change.granted, ['admin'])
  assert.deepEqual(w.calls.map((c) => [c.peer, c.status]), [['identity', 200]])
  assert.equal(w.exchanges, 1)
  assert.equal(count401(w), 0)
})

test('MARKET AND BILLING STILL RELAY THE OPERATOR, and the fix did not quietly take that away', async () => {
  // SD-11: those two guards admit a user token with `role:admin`, so the UPSTREAM'S audit names the
  // human — market records `resolvedBy: <the operator>` and billing records `actor: user:<id>`.
  // This is the property most likely to be lost in a refactor that makes "the token" uniform, and
  // it would be invisible in every outcome: the case still resolves, it is just attributed to a
  // service instead of to a person. The fake peers 403 a service JWT to make that loss loud.
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, CREDENTIAL, null)

  const resolved = await upstreams.market.resolveCase({
    caseId: 'case-1',
    state: 'upheld',
    notes: 'confirmed',
    correlationId: CORRELATION,
    operatorBearer: 'the-operators-own-bearer',
  })
  const revoked = await upstreams.billing.revokeEntitlement({
    entitlementId: 'ent-1',
    reason: 'chargeback',
    refund: true,
    correlationId: CORRELATION,
    operatorBearer: 'the-operators-own-bearer',
  })

  assert.equal(resolved.id, 'case-1')
  assert.equal(revoked.alreadyRevoked, false)
  assert.deepEqual(
    w.calls.map((c) => c.token),
    ['the-operators-own-bearer', 'the-operators-own-bearer'],
    'a service token was sent where the operator’s own bearer belongs — the upstream audit now names admin-api, not the human',
  )
  // And nothing was minted: neither call needs this service's own identity at all.
  assert.equal(w.exchanges, 0)
})

test('no credential and no token sends NOTHING, rather than an unauthenticated request', async () => {
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, null, null)
  assert.equal(upstreams.mode, 'none')

  // **Nothing is sent.** Resolving `''` or `undefined` would have gone out as a bare `Bearer ` or
  // with no header at all, come back 401, and been rendered by the estate view as the LEDGER being
  // unwell — when the truth is that nobody configured admin-api. Those are different mornings.
  // `ServiceTokenUnavailableError` is 503 under `statusFor`, never 401, for the same reason
  // `Verifier` answers 503 on an unreachable JWKS.
  await assert.rejects(
    async () => upstreams.ledger.reverseEntry(reversal),
    (err: unknown) =>
      err instanceof UpstreamError && err.status === null && /ADMIN_API_IDENTITY_CREDENTIAL/.test(String(err.cause ?? '')) === false,
    'a request went out with no credential configured',
  )
  assert.deepEqual(w.calls, [], 'an unauthenticated request was sent to the ledger')
})

test('the reason a `none` deployment cannot authenticate is NAMED, not inferred', async () => {
  // The message an operator reads at three in the morning. It names the variable to set and where
  // it already exists, because "401 from ledger" sent the last one to the wrong service.
  clockAt(0)
  const w = await world()
  const upstreams = upstreamsFor(w, null, null)

  await assert.rejects(
    async () => upstreams.clientConfig.serviceToken(),
    (err: unknown) =>
      err instanceof ServiceTokenUnavailableError &&
      /ADMIN_API_IDENTITY_CREDENTIAL/.test(err.message),
  )
})
