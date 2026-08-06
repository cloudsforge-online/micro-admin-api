# cloudsforge-admin-api

[![ci](https://github.com/cloudsforge-online/micro-admin-api/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-admin-api/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

The operator BFF. **Cross-service operator actions behind a two-operator approval queue, a
tamper-evident hash-chained audit mirror, feature flags and broadcasts.**

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

Per [`03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md),
this supersedes `platform/services/nimbus`'s admin proxies. Nimbus's audit is
`log.warn({audit: …})` — a log line, which is sampled, expires, and can be lost under load (SD-11)
— and its two proxies call bare `fetch` with no total-request timeout, so a hung ForgeKeyvault
pins the identity service indefinitely (`routes/vault.ts`, `routes/pay.ts`).

## The one rule

> **An operator acts as themselves, and every action they take is in the chain.**

There is no route here that takes a `userId` and acts for it. A user is only ever a **subject** —
the thing acted upon — never a costume. The frozen estate's `/internal/*` routes were an
act-as-anyone primitive and `deploy/gateway/dynamic/policy.yml` refuses them from outside for
exactly that reason; nothing here is an equivalent, and `server.test.ts` asserts the absence
against this repository's own source.

## Routes

| Route | What it is |
| --- | --- |
| `POST /v1/events` | The audit mirror intake. **HMAC only — no bearer is read.** Verified with `contracts-events`' `verifyDelivery` over the raw bytes, **before** they are parsed. The signature *is* the authentication: no outbox relay in the estate can present a token, and demanding one meant the event bus was refused by the route built to receive it. |
| `GET /v1/audit` | The estate's audit of record, filtered by actor, action, subject or correlation id. |
| `GET /v1/audit/verify` | Walk the chain and report every break. 200 either way; `ok` is the signal. |
| `GET /v1/actions` | The closed action catalogue, including the one that is blocked and why. |
| `POST /v1/approvals` | Raise a request. Two operators, or nothing happens. |
| `GET /v1/approvals` `GET /v1/approvals/:id` | The queue. |
| `POST /v1/approvals/:id/decision` | Approve or reject — **and execute**, if approved. |
| `GET /v1/flags` `PUT /v1/flags/:key` | Feature flags. Owner and description are mandatory. |
| `GET /v1/broadcasts` `POST /v1/broadcasts` `DELETE /v1/broadcasts/:id` | Operator broadcasts. Retracted, never deleted. |
| `GET /v1/engagement/policies` | The engagement caps and their schema ceilings, plus the fee-recycle percentage. |
| `PUT /v1/engagement/policies/:service` | **Lower** a cap, one operator. A raise is refused here with 403 and the name of the action that does it. |
| `GET /v1/engagement/report` | Treasury and per-service balances read off the ledger, spend, and the transfer records. |
| `GET /v1/estate` | One call, one 200, six tiles, per-tile degradation. |
| `GET /livez` `GET /readyz` `GET /metrics` | Rule 4. |

Every mutating route requires an `Idempotency-Key`. `routeidempotency.test.ts` enumerates them
from `server.ts`'s source and fails on one that neither wraps the guard nor states why it need
not — the guard `micro-market` gained after two routes were found with none.

---

## 1. Does granting a platform role belong to this service?

**The decision splits three ways, and only the middle part is mine.**

[`18-build-status.md` §3.3g](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/18-build-status.md) records — verified against a
running deployment rather than reasoned about — that the estate cannot bootstrap itself.
Re-checked here against source, all three claims hold:

| Claim | Verified at |
| --- | --- |
| `POST /service-tokens` requires the `admin` role | `identity/src/server.ts`, via `authenticateAdmin` |
| `users.roles` is `text[] not null default '{}'` | `identity/src/migrations.ts` |
| No route in identity grants a platform role | All 36 route definitions enumerated. `POST /auth/register` hard-codes `['player']` (`identity/src/users.ts`); `POST /organisations/:id/memberships` grants an **organisation** role, which SD-03 is explicit is not a platform role. |

**The write belongs to identity.** `users.roles` is identity's column in identity's database. Rule
1 of `03` §2 — one database, and no service reads another's — is enforced by a CI check that greps
this repository's source for any connection string that is not `ADMIN_API_DATABASE_URL`. So this
is not a matter of taste: a version of this service that granted a role by writing to identity
would fail its own build, and correctly.

**The authorisation belongs here, and is built.** Granting `admin` is the most audit-worthy action
in the estate — an operator who can grant it can grant it to anyone, including to an account they
control — so it is a two-operator action with a mandatory reason code and a hash-chained audit
row, exactly like a manual ledger reversal. That machinery is in this repository, is exercised end
to end by the actions that *do* have an upstream route, and `identity.role.grant` is a first-class
entry in the catalogue. **It now has an executor**, because identity has built the route this
repository specified — see below.

**The bootstrap belongs to neither, deliberately.** A service that can mint its own first `admin`
is a service whose compromise grants the estate — and this service's own queue cannot authorise
the first grant anyway, because approving requires an operator who already holds the role.
Bootstrap stays outside every service: one `update users set roles = array['admin']` under the
database owner's credentials, which is what `scripts/slice-verify.sh` already does and asserts.
That is the correct home for a step that should require access to the database and should live in
a runbook rather than in an API.

**`POST /v1/approvals` with `action: 'identity.role.grant'` used to answer 501**, naming the route
identity had to grow rather than accepting a request the queue could never execute. A queue that
accepts work it cannot do lies to the operator waiting on it, and would leave a row sitting at
`approved` for ever — which reads in the audit as two operators having authorised something that
never happened.

**The route landed, so the action executes.** `micro-identity` built it in the shape specified:

```
PUT /internal/users/:id/roles      body: { roles, actor, reason, approvalId }
guard: a SERVICE token holding `identity:admin` — NOT `authenticateAdmin`, which refuses a
       service token outright and would make the route unreachable from here
write: a platform_role_grants row, source='approval', in the SAME transaction as the
       users.roles update, behind a deferred trigger that refuses the update without it
```

It was **not** the "about ten lines" this file predicted, and the difference matters.
`setPlatformRoles` **replaces** the role set rather than adding to it, and every registered user
holds `player` — so a naive `roles: [role]` would have revoked `player` from every operator it
promoted, a privilege removal disguised as a grant. The executor sends the union instead. Two tests
break on the two silent failure modes: the revocation, and a missing `approvalId` (which identity's
CHECK refuses, since it pairs `source='approval'` to it as an equality rather than an implication).

**What has not changed is the thing that matters.** This service is still not the escalation route.
Executing requires an approval two *distinct* operators signed, which requires an administrator to
already exist; the first still comes from identity's one-shot deploy-time bootstrap, refused on
re-run by a partial unique index no client can route around. `bootstrap.test.ts` holds that line
from this side, and its pin was changed deliberately and in the open rather than deleted.

**Still owed by `micro-deploy`:** this service's token does not yet carry `identity:admin`
(`deploy/compose/docker-compose.estate.yml`). Until it does the executor is correct and will
`403` at identity in a real deployment. It is therefore proven against a fake upstream, as every
other executor here is, and **not** yet end-to-end against the running estate.

---

## 2. Which scope matcher, and why

**Exact match only, on this service, deliberately.** `src/scopes.ts`.

[`§3.3h`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/18-build-status.md) records two matchers that disagree:

| Package | Line | Semantics |
| --- | --- | --- |
| `contracts/packages/auth` | `src/index.ts` | `granted.includes(required)` — exact only |
| `runtime/packages/auth` | `src/index.ts` | one wildcard level: `foo:*` grants `foo:bar` |

**Neither package is changed by this repository**, per §3.3h's conclusion that changing an
authorisation matcher is the highest-blast-radius edit available here and wants the owner rather
than an agent. This service imports `@cloudsforge/auth` from **runtime**, as every service does,
and then deliberately does not call its `hasScope`. `requireExactScope` uses `includes`.

1. **The blast radius is asymmetric.** Over-granting on the operator surface hands somebody the
   estate; under-granting hands somebody a 403 they can get fixed in a morning. When two readings
   are both defensible, the one whose failure is recoverable wins.
2. **`admin:*` is exactly the credential this estate exists to remove.** The wildcard form is
   documented and deliberate in runtime — a *bare* `*` still grants nothing — but `admin:*` is one
   string that grants reading the estate's audit of record. That is `PAY_SERVICE_TOKEN` with a new
   spelling (SD-05, SD-12).
3. **`micro-devplatform` already navigated it this way**, using `includes` rather than `hasScope`
   on `/internal/keys/verify`. A credential service and an operator surface should not be the two
   places the estate discovers its wildcard semantics differ.

The cost is stated rather than hidden: a token issued as `admin:*` is refused here and accepted by
a sibling that calls `hasScope`. `scopes.test.ts` pins that in both directions, including a test
that calls runtime's `hasScope` on the same principal and asserts it *would* have granted it — so
the difference is a recorded decision rather than a 403 somebody has to reverse-engineer.

**And the scope nobody has.** The vocabulary is one scope: `admin:read`. There is no
`admin:execute`. A service token can read and nothing else; it cannot request, approve or execute.
Approval is consent given by a person, and a service token that could approve would make four eyes
satisfiable by two credentials sitting on one machine.

**`admin:audit:write` is gone, and that is a repair rather than a relaxation.** It gated the audit
mirror, and no producer in this estate could present it: an outbox relay is a background job woken
by a Postgres poll, and every one of the twenty-one relays in the estate sends the delivery
signature and the event id and nothing else. The mirror also verified a signature format this
repository had invented and nobody sends. Both were measured against the running estate — a
correctly signed delivery answered `401 bad_signature`, and the local format with no bearer
answered `401 unauthenticated` — so the estate's audit of record received nothing at all. The
scope constant was deleted rather than left unreferenced; a scope in a published vocabulary that no
route checks is a capability this service claims and does not have.

---

## 3. How the audit chain detects tampering

Each row commits to its predecessor: `hash = SHA-256(prev_hash ‖ every other column)`. Every
column on `audit_events` is hashed, including `seq`, which the appender takes from the sequence
*before* the insert so a reordering is detectable as well as an edit. Fields are length-prefixed —
without framing, `actor='ab' + action='c'` and `actor='a' + action='bc'` produce identical bytes,
and two different rows would share a hash.

| Attack | Detected by | Test |
| --- | --- | --- |
| A field is edited | `H(row)` no longer matches the stored hash **and** no longer matches the next row's `prev_hash` | `TAMPER: an edited field is detected, at the row it was edited` |
| A payload is edited | same | `TAMPER: editing the payload is detected too` |
| An interior row is deleted | the next row names a predecessor that is not the row before it | `TAMPER: a deleted interior row is detected, at the gap` |
| The tail is truncated | **a checkpoint** — see below | `TAMPER: a truncated tail is detected — but ONLY against a checkpoint` |
| The whole chain is re-hashed after an edit | **a checkpoint** | `TAMPER: a re-hashed forgery verifies, and is caught by the checkpoint` |

**The honest part.** A hash chain does not detect truncation on its own: remove the last N rows
and what remains is a shorter chain that verifies perfectly. That is the attack somebody covering
their tracks would actually run, because it needs no forgery. `audit_chain_checkpoints` is the
answer — the verification job records "the chain reached seq S with head H and N events", so a
truncation below a checkpoint names a row that is no longer there. An attacker who can also delete
the checkpoint defeats it; the point is that they now have to alter two tables consistently, and
the checkpoint row is what an off-host backup carries. **Both directions are tests**: the
truncated-chain test asserts the checkpoint catches it *and* asserts that without the checkpoint
the remainder verifies. A claim of tamper-evidence that overstates itself is worse than none.

**A fork is unrepresentable, not merely detectable.** `audit_events_chain_uniq` makes a hash the
predecessor of at most one row, so two appenders that both read the same head cannot both commit.
`appendAudit` also takes `pg_advisory_xact_lock`, so they queue rather than race. Ten concurrent
appends produce a gapless chain of ten (`concurrent appends serialise into one chain rather than
forking`).

**The verifier refuses to checkpoint a broken chain.** Checkpointing an unverified head would
anchor the tamper: the next pass would resume from a row the attacker wrote and declare everything
before it good. It also resumes one row *before* the checkpoint, so the anchoring row is re-checked
rather than trusted — a verifier that trusts its own starting row can be aimed past the tamper.

**And what it does not survive:** an attacker who can rewrite the whole table, recompute every
hash, and rewrite the checkpoints, in one transaction, between nightly verifications. Nothing
stored beside the data it attests can. The chain raises the cost from one `UPDATE` to that, and
SD-16 runs the verifier nightly and calls a break a P0.

---

## 4. Four eyes

`13-operational-model.md`: self-approval "is refused by the service, not by documentation".
Enforced three times, and proved three times with the layer above bypassed each time:

1. `decide()` refuses it with a `SelfApprovalError` → HTTP 403 `self_approval_refused`.
2. The UPDATE carries `and requested_by <> $operator`, so a concurrent decision cannot slip past.
3. `approvals_no_self_approval` is a CHECK constraint, so no code path — including one written
   next year — can get past it.

Every one of those tests also asserts the **other direction**: a different operator succeeds. A
refusal that refused everybody would pass the first half of all three.

Two more constraints carry the rest of it. `approvals_execution_needs_approval` means a row cannot
record an execution unless it is `approved` — an action that ran without a second pair of eyes
cannot be written down. `approvals_decision_is_attributed` means `expired` carries no decider,
because nobody decided anything, which is what makes an expired request unexecutable by
construction rather than by a state check somebody could reorder.

**Execution is a separate transaction, deliberately, and is not rolled back on failure.** An HTTP
call cannot be inside a database transaction. So the decision commits and then the action runs; a
failure leaves an `approved`, `execution_outcome = 'failed'` row, which is the honest state and
the one an operator can act on. Rolling the approval back would erase the record that two
operators agreed and would need a third signature for something already authorised twice. Every
executor is idempotent at its upstream — the ledger reversal derives its key from the approval id
— so a retry is safe.

---

## 5. Which credential each upstream call carries

Not uniform, and the asymmetry is the interesting part. SD-11 records something the frozen estate
got right: "Nimbus's admin proxies forward the operator's own bearer token rather than a service
secret, which is a genuinely good decision: Pay and custody record *which* administrator acted."
That is preserved — but only where the upstream can accept it.

| Upstream | Route (cited) | Credential | Why |
| --- | --- | --- | --- |
| `market` | `POST /v1/moderation/cases/:id/resolve` — `market/src/server.ts` | **the operator's own bearer** | `requireOperator` admits a user token with `role:admin`, and market derives `resolvedBy` from the principal. Market's own record names the human. |
| `billing` | `POST /entitlements/:id/revoke` — `billing/src/server.ts` | **the operator's own bearer** | same: `isAdmin(principal)` branch, `actor` derived from the principal. |
| `ledger` | `POST /entries/:id/reverse` — `ledger/src/server.ts`, scope `ledger:post` | **this service's service token** | `authorise` refuses a user principal outright, and no route does otherwise. The ledger records `service:admin-api`. |

For the ledger the human is not lost — the entry's `metadata.operator` names them, this service's
chain names them, and both carry the same `correlationId` — but the ledger's own record is less
specific than ours, and `metadata.operatorRecordedIn` says where to look. That is stated rather
than hidden because it is the one place in this service where an upstream knows less about "who"
than we do.

Every route above was read in the provider's source. `upstreams.test.ts` asserts the exact path,
the exact body field names and the exact bearer for each, against a real HTTP socket — because
clients in this estate have repeatedly been built against imagined surfaces
(`docs/ecosystem/18-build-status.md` §3.3i, §3.3m).

---

## 6. What was deliberately not ported from nimbus

| Nimbus had | Here |
| --- | --- |
| **The pay admin proxy** | **Deleted, not ported.** `03:151` records it is "deleted outright once the gateway handles CORS", and `deploy/gateway/dynamic/` now does. |
| **The vault admin proxy / key reveal** | **Deleted.** `03:162`: replaced by the user export ceremony (AD-13) and a two-operator break-glass runbook. A route that can return key material is a P0 in 17 §8 whatever else it does. |
| `log.warn({audit: …})` | A transactional hash-chained row (SD-15). Logs are sampled and expire by design; an audit record that can be dropped under load is not an audit record. |
| Bare `fetch`, no timeout | `@cloudsforge/http` with an absolute deadline, bounded retries and a per-upstream circuit breaker. A wedged upstream is asserted to be bounded by the deadline, using a socket that accepts and then writes nothing. |
| An operator's bearer forwarded to upstreams | **Kept** — it was the right call. Section 5. |

Also not built, deliberately:

- **No emergency freeze.** SD-11 makes freeze authority *asymmetric* — set by one operator,
  cleared by two — and that cannot be expressed by anything in this repository today, because the
  thing being frozen lives in ledger and policy. When it lands it goes through the approval queue
  for the clear and a single-operator route for the set, and both halves belong in the same change.
- **No notification surface.** A broadcast is an unaddressed statement on a public page. Nothing
  here holds a `user_id`, a read state or a preference — those are notify's, and 17 §7 row 8
  requires a `critical` security notification to be delivered *despite* preferences, which is a
  decision for the service that knows who the message is for. `flags.test.ts` asserts the
  `broadcasts` table has no such column.
- **No cache.** `hub-api` caches because a dashboard is drawn by every user on every page load.
  This surface is drawn by a handful of operators during incidents, and an operator acting on a
  ninety-second-old "ledger: ok" is acting on a fact that has changed. Every tile is fetched live,
  with a deadline, and `cache-control: no-store` is on every response.

---

## 7. The engagement treasury: the caps, before a single Shard moves

`docs/ecosystem/21` decides the platform may fund empty rooms — bounded, disclosed, denominated in
Shards — and its §8 build order is law: **nothing may move a Shard before the caps exist.** This
service holds the caps because it already owns cross-service operator state (21 §4). The money it
caps lives elsewhere, and that refusal is the design: `platform:engagement-treasury` and
`engagement:<service>` are ordinary `micro-ledger` accounts (grammar:
`contracts/packages/money/src/index.ts`; the ledger's own schema is untouched — its `subject`
column is unconstrained text at `ledger/src/migrations.ts`), and an auditor reconstructs the
whole programme from the ledger alone.

What migration 8 (`src/migrations.ts`, version 8) makes unrepresentable rather than merely checked:

| Claim (21 §7) | The line that enforces it |
| --- | --- |
| A transfer above the policy cap is refused **even for a caller holding a connection** | trigger `engagement_transfers_within_cap` — raises on `amount_shards > transfer_cap_shards`, and on a service with **no policy row at all** |
| A transfer not backed by an approved `engagement.transfer` approval cannot be recorded | same trigger — the approval row must exist, be `approved`, and name that action |
| Every transfer resolves to a ledger entry; a `posted` row with no entry cannot exist | CHECK `engagement_transfers_posted_names_entry` — `posted` ⇔ `ledger_entry_id` ⇔ `posted_at` |
| One approval is one transfer, for ever | `engagement_transfers_one_per_approval` unique on `approval_id` — the same key the ledger idempotency key is derived from |
| The fee-recycle percentage cannot exceed its ceiling | CHECK `engagement_fee_recycle_within_ceiling` (0–2500 bps) |
| Raising any cap without an approval is refused; lowering succeeds | trigger `engagement_raise_needs_approval` — a raise must name a **fresh** approved `engagement.policy.set` approval; a lower needs nothing |
| Every ceiling is finite | CHECKs `engagement_policies_cap_within_ceiling` (10⁹ Shards), `engagement_policies_seed_within_ceiling` (10²¹/10²² wei) — the same numbers `micro-foresight` pins in its own schema |

Every row of that table is fire-tested with raw SQL in `src/engagement.test.ts`, connection in
hand, routes bypassed.

The three actions (21 §6), in the catalogue at `src/actions.ts`:

- **`engagement.transfer`** — two operators. The executor claims the cap-checked transfer row,
  posts **one** balanced entry to `POST /entries` (`ledger/src/server.ts`) with both accounts
  inline so the ledger creates them idempotently on first use (`ledger/src/accounts.ts`), then
  records the pairing. Idempotent end to end on the approval id.
- **`engagement.policy.set`** — two operators, **required only to raise**. The lowering lane is
  `PUT /v1/engagement/policies/:service`, one operator — `micro-devplatform`'s quota asymmetry
  (`devplatform/src/server.ts`: *the direction is the authority*), with the trigger holding the
  line against any writer that skips the route. `:service` may be `platform`, which addresses the
  fee-recycle percentage; it starts at 0 (21's recorded open decision — pure mined funding until
  revenue exists).
- **`engagement.report`** — no approval; 21 §6's column reads "none (read)". The queue **refuses**
  it and names `GET /v1/engagement/report`, the way the blocked action's 501 names its missing
  route: a read that spent two signatures would train operators to sign reflexively.

Not in this phase, recorded not hidden: the transfers only *fill* the per-service accounts. The
grants that spend them (market subsidies, worlds/title budgets, trade credits — 21 §5) and the
`admin-web` screen are later waves of the same programme, behind foresight's house seed.

---

## Degradation

`GET /v1/estate` always answers 200. Every tile carries its own status, `data` is never null, and
a dead upstream marks **one** tile. `TILE_SOURCES` in `src/estate.ts` records which upstream feeds
which tile as data; the degradation suite reads it, so a tile that quietly acquires a second
dependency fails the build.

The half that catches regressions is the other half: **every unaffected tile is still `ok`**. With
all four upstreams down the route still answers 200 and the three self-owned tiles — audit,
approvals, broadcasts — are still `ok`, which is the point. The console is read *during* the
incident; 17 §7 row 9 measures this whole surface on an operator answering a question "without a
`docker logs`".

Alert on `admin_estate_tile_status_total`, not on the HTTP error rate. A view serving 200s with two
dead tiles is healthy in `http_requests_total` by design, so the signal has to live in the tile
counter.

## Background work

No `setInterval` — asserted in CI *and* by a test that reads every non-test source in `src/`. Four
leased jobs, each keyed on the **contended resource** rather than on a row:

| Job | Lease key | Why that key |
| --- | --- | --- |
| `audit.verify` | `audit:chain` | There is one chain. Two verifiers would both write a checkpoint. Nightly, per SD-16. |
| `outbox.relay` | `outbox` | One unpublished stream. Two relays deliver every event twice. |
| `approvals.expire` | `approvals` | Expiry writes an audit row per request. Two expirers would show one expiry twice in the audit of record. |
| `idempotency.reap` | `idempotency` | One table, one DELETE loop. |

`jobs.test.ts` proves two workers on one job produce one run, ten workers on four jobs claim each
job exactly once, and two expirers on one overdue request write exactly one audit row.

## Tests

`pnpm test` — **275 tests, 0 skipped**, against a real Postgres whose name must contain `test`.

The exit criteria are the two files that carry them: `audit.test.ts` performs four tampers and
asserts each is caught by the specific break kind at the specific sequence, and `approvals.test.ts`
proves the four-eyes refusal three times with the layer above bypassed each time.

## Gaps: things this service needs that do not exist

Each is a place where the honest behaviour today is a 501, a degraded tile, or a route this service
does not offer. None is worked around, because working around a missing route is how a BFF acquires
state.

1. **`PUT /internal/users/:id/roles` on identity.** Section 1. Until it exists the estate cannot
   issue its first service token without a hand-written `UPDATE`, and this service refuses to
   pretend otherwise.
2. **The mirror now receives events, and what remains is a deploy question.** `POST /v1/events`
   reads the domain topics that already exist rather than a `*.audit.recorded` stream nobody
   publishes, and it is now reachable by the relays that send them: the route speaks
   `contracts-events`' signing scheme (`cf-signature`) and authenticates with the MAC alone. The
   shared `OUTBOX_SIGNING_SECRET` is already configured for this service in
   `deploy/compose/docker-compose.estate.yml`, with the same value every producer signs with,
   so no deploy change is needed to make delivery work.

   What `micro-deploy` still owes is the **subscriptions**: a producer only delivers here if a row
   in its `event_subscriptions` names this service's `/v1/events` for that topic. That is
   per-producer configuration and is reported to the owners of those repositories rather than
   changed from here.

   **Rotating the shared secret.** `OUTBOX_SIGNING_SECRET` is one key held by 24 services, and its
   current value is a placeholder committed to a public file, so it has to be rotated. It signs the
   outbox→inbox hop, so if a producer moves to a new key while this receiver holds only the old one,
   delivery partitions **silently** — and what goes quiet is the estate's audit of record, which
   during an incident is indistinguishable from "nothing happened". So the receiving side takes a
   list:

   | Variable | Required | What it does |
   |---|---|---|
   | `OUTBOX_SIGNING_SECRET` | yes | The single key this service **signs** its own outbox deliveries with. Never a list: a producer signing under two keys has not rotated, it has forked. |
   | `OUTBOX_ACCEPT_SECRETS` | no | Comma-separated, **newest first**. The keys `POST /v1/events` will **accept**. Unset, it is exactly `[OUTBOX_SIGNING_SECRET]`, which is today's behaviour byte for byte — so deploying this is a no-op, and that is what lets the rotation be staged one service at a time. Each entry is validated like the signing secret — `@cloudsforge/secrets` asserts the SHAPE of a generated key (base64 or hex, 32 decoded BYTES, an entropy floor), replacing the deny-list-plus-24-CHARACTER-floor that micro-org #142's 40-character placeholder walked straight through — and a repeated entry is refused at boot. |

   The duplicate rule is not tidiness. `verifyDelivery` reports the **index** of the key that
   matched, and this route logs a warning naming it whenever it is not 0. That warning going quiet
   across every producer is the signal that says the rotation has finished and the old key can be
   dropped; a duplicated entry would make it ambiguous.

   **Residual risk, stated rather than buried.** `source` is now the envelope's `producer` rather
   than a scope-checked principal, so any holder of the estate outbox secret can mirror a row
   attributed to any producer. `validateEnvelope` still requires a producer to own its topic
   namespace, so a forged row must at least be internally consistent, and the secret is held only
   by services. Restoring the stronger property needs a **per-producer signing secret** rather than
   one estate-wide secret — a `micro-deploy` and `contracts-events` change, recorded here and in
   `server.ts` rather than pretended away.
3. **`@cloudsforge/contracts-admin` is uncut**, so the scope vocabulary and the action catalogue
   live in this service rather than in a published, schema-diff-enforced package.
4. **No emergency freeze**, because its asymmetry spans ledger and policy. See §6.
5. **Found while reading, reported not fixed** (this repository does not edit siblings):
   **the outbox relay's comment overstates what it does, in eighteen repositories.**

   `service-template/src/outbox.ts` — and therefore `billing`, `custody`, `devplatform`,
   `emberkin`, `foresight`, `identity`, `indexer`, `ledger`, `market`, `mint`, `nda`, `pricing`,
   `settlement`, `studio`, `trade`, `wallet` and `worlds`, all carrying it verbatim — says:

   > A subscriber added after the event was written still receives it, because the delivery rows
   > are computed from the live subscription set on every pass rather than fixed when the event was
   > produced.

   The second clause is true and the first does not follow from it. With **zero active
   subscriptions** the outstanding count is zero, so the event is marked `published_at` on the very
   first pass and is never reconsidered — a subscriber added after that receives nothing. The claim
   holds only while an event is still *outstanding*, i.e. while some other subscriber has yet to be
   delivered.

   The behaviour is right — a subscription is not a replay request — so this is a documentation
   defect rather than a code one, and it should be corrected in `service-template` first or it will
   keep propagating to every new service. It matters because the sentence reads as a guarantee an
   integrator could plan around: "just add the subscription, you will not miss anything."

   This repository's copy states the limit precisely and pins both directions in `outbox.test.ts`
   (`a subscriber added while an event is OUTSTANDING does receive it` and `THE LIMIT: a subscriber
   added after the event PUBLISHED does not receive it`).

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
