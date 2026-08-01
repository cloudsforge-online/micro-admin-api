# cloudsforge-admin-api

The operator BFF. **Cross-service operator actions behind a two-operator approval queue, a
tamper-evident hash-chained audit mirror, feature flags and broadcasts.**

Per [`03-repository-responsibilities.md:50`](../docs/ecosystem/03-repository-responsibilities.md),
this supersedes `platform/services/nimbus`'s admin proxies. Nimbus's audit is
`log.warn({audit: …})` — a log line, which is sampled, expires, and can be lost under load (SD-11)
— and its two proxies call bare `fetch` with no total-request timeout, so a hung ForgeKeyvault
pins the identity service indefinitely (`routes/vault.ts:61`, `routes/pay.ts:73`).

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
| `POST /v1/events` | The audit mirror intake. Signature-checked **before** it is parsed. |
| `GET /v1/audit` | The estate's audit of record, filtered by actor, action, subject or correlation id. |
| `GET /v1/audit/verify` | Walk the chain and report every break. 200 either way; `ok` is the signal. |
| `GET /v1/actions` | The closed action catalogue, including the one that is blocked and why. |
| `POST /v1/approvals` | Raise a request. Two operators, or nothing happens. |
| `GET /v1/approvals` `GET /v1/approvals/:id` | The queue. |
| `POST /v1/approvals/:id/decision` | Approve or reject — **and execute**, if approved. |
| `GET /v1/flags` `PUT /v1/flags/:key` | Feature flags. Owner and description are mandatory. |
| `GET /v1/broadcasts` `POST /v1/broadcasts` `DELETE /v1/broadcasts/:id` | Operator broadcasts. Retracted, never deleted. |
| `GET /v1/estate` | One call, one 200, six tiles, per-tile degradation. |
| `GET /livez` `GET /readyz` `GET /metrics` | Rule 4. |

Every mutating route requires an `Idempotency-Key`. `routeidempotency.test.ts` enumerates them
from `server.ts`'s source and fails on one that neither wraps the guard nor states why it need
not — the guard `micro-market` gained after two routes were found with none.

---

## 1. Does granting a platform role belong to this service?

**The decision splits three ways, and only the middle part is mine.**

[`18-build-status.md` §3.3g](../docs/ecosystem/18-build-status.md) records — verified against a
running deployment rather than reasoned about — that the estate cannot bootstrap itself.
Re-checked here against source, all three claims hold:

| Claim | Verified at |
| --- | --- |
| `POST /service-tokens` requires the `admin` role | `identity/src/server.ts:1266`, via `authenticateAdmin` at `:545` |
| `users.roles` is `text[] not null default '{}'` | `identity/src/migrations.ts:119` |
| No route in identity grants a platform role | All 36 route definitions enumerated. `POST /auth/register` hard-codes `['player']` (`identity/src/users.ts:104-106`); `POST /organisations/:id/memberships` (`:1229`) grants an **organisation** role, which SD-03 is explicit is not a platform role. |

**The write belongs to identity.** `users.roles` is identity's column in identity's database. Rule
1 of `03` §2 — one database, and no service reads another's — is enforced by a CI check that greps
this repository's source for any connection string that is not `ADMIN_API_DATABASE_URL`. So this
is not a matter of taste: a version of this service that granted a role by writing to identity
would fail its own build, and correctly.

**The authorisation belongs here, and is built.** Granting `admin` is the most audit-worthy action
in the estate — an operator who can grant it can grant it to anyone, including to an account they
control — so it is a two-operator action with a mandatory reason code and a hash-chained audit
row, exactly like a manual ledger reversal. That machinery is in this repository, is exercised end
to end by the three actions that *do* have an upstream route, and `identity.role.grant` is a
first-class entry in the catalogue. What it does not have is an executor, because there is nothing
to call.

**The bootstrap belongs to neither, deliberately.** A service that can mint its own first `admin`
is a service whose compromise grants the estate — and this service's own queue cannot authorise
the first grant anyway, because approving requires an operator who already holds the role.
Bootstrap stays outside every service: one `update users set roles = array['admin']` under the
database owner's credentials, which is what `scripts/slice-verify.sh` already does and asserts.
That is the correct home for a step that should require access to the database and should live in
a runbook rather than in an API.

**So `POST /v1/approvals` with `action: 'identity.role.grant'` answers 501**, naming the route
identity must grow, rather than accepting a request the queue can never execute. A queue that
accepts work it cannot do lies to the operator waiting on it, and would leave a row sitting at
`approved` for ever — which reads in the audit as two operators having authorised something that
never happened.

**The route identity needs**, specified so the day it lands this changes in one file:

```
PUT /internal/users/:id/roles      body: { roles: string[], actor: string, reason: string }
guard: a SERVICE token holding `identity:admin` — NOT `authenticateAdmin`, which refuses a
       service token outright (identity/src/server.ts:540) and would therefore make the
       route unreachable from here for the same reason the bootstrap is unreachable now
audit: an `identity.role.changed` row in the same transaction, per SD-15's Identity row
```

With that in place, `EXECUTORS['identity.role.grant']` is about ten lines and the 501 test fails —
which is why the test is written the way it is.

---

## 2. Which scope matcher, and why

**Exact match only, on this service, deliberately.** `src/scopes.ts`.

[`§3.3h`](../docs/ecosystem/18-build-status.md) records two matchers that disagree:

| Package | Line | Semantics |
| --- | --- | --- |
| `contracts/packages/auth` | `src/index.ts:209` | `granted.includes(required)` — exact only |
| `runtime/packages/auth` | `src/index.ts:178` | one wildcard level: `foo:*` grants `foo:bar` |

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

**And the scope nobody has.** The vocabulary is two scopes: `admin:read` and `admin:audit:write`.
There is no `admin:execute`. A service token can read and it can mirror an audit row; it cannot
request, approve or execute. Approval is consent given by a person, and a service token that could
approve would make four eyes satisfiable by two credentials sitting on one machine.

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

`13-operational-model.md:757`: self-approval "is refused by the service, not by documentation".
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
| `market` | `POST /v1/moderation/cases/:id/resolve` — `market/src/server.ts:1086` | **the operator's own bearer** | `requireOperator` admits a user token with `role:admin`, and market derives `resolvedBy` from the principal. Market's own record names the human. |
| `billing` | `POST /entitlements/:id/revoke` — `billing/src/server.ts:544` | **the operator's own bearer** | same: `isAdmin(principal)` branch, `actor` derived from the principal. |
| `ledger` | `POST /entries/:id/reverse` — `ledger/src/server.ts:394`, scope `ledger:post` | **this service's service token** | `authorise` refuses a user principal outright, and no route does otherwise. The ledger records `service:admin-api`. |

For the ledger the human is not lost — the entry's `metadata.operator` names them, this service's
chain names them, and both carry the same `correlationId` — but the ledger's own record is less
specific than ours, and `metadata.operatorRecordedIn` says where to look. That is stated rather
than hidden because it is the one place in this service where an upstream knows less about "who"
than we do.

Every route above was read in the provider's source. `upstreams.test.ts` asserts the exact path,
the exact body field names and the exact bearer for each, against a real HTTP socket — because six
times in this estate a client was built against an imagined surface.

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

`pnpm test` — **257 tests, 0 skipped**, against a real Postgres whose name must contain `test`.

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
2. **No service mirrors its audit rows yet.** `POST /v1/events` is built, signed, scoped and
   deduped, but nothing publishes `*.audit.recorded`. 17 §2 requires every service to; the mirror
   is therefore empty in a real deployment until each of them emits. The topic is not registered in
   `contracts/packages/events` either — the same finding `micro-devplatform` recorded for
   `devplatform.*` at `contracts/packages/events/src/index.ts:222`.
3. **`@cloudsforge/contracts-admin` is uncut**, so the scope vocabulary and the action catalogue
   live in this service rather than in a published, schema-diff-enforced package.
4. **No emergency freeze**, because its asymmetry spans ledger and policy. See §6.
5. **Found while reading, not fixed here** (this repository does not edit siblings):
   `market/src/outbox.ts:239-241` claims "a subscriber added after the event was written still
   receives it". With zero active subscriptions the outstanding count is zero, the event publishes
   on the first pass and is never reconsidered — so a subscriber added after publication does not
   receive it. The behaviour is right; the comment is not. This repository's copy states the limit
   precisely and pins both directions in `outbox.test.ts`.
