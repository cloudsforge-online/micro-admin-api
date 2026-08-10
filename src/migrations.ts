/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service asserts the version rather than reaching it.
 *
 * ---------------------------------------------------------------------------------------------
 * **THE FOUR CONSTRAINTS THIS SERVICE EXISTS TO ADD. Each is a database constraint, not a rule
 * in a route, because the route is the thing an attacker is trying to get past.**
 *
 *   `audit_events_chain_uniq`        A hash may be the predecessor of AT MOST ONE row. This is
 *                                    what makes the audit log a chain rather than a tree: two
 *                                    concurrent appenders that both read the same head cannot
 *                                    both commit, so there is exactly one history and a fork is
 *                                    unrepresentable rather than merely detectable. Everything
 *                                    `audit.ts` does rests on this one line.
 *
 *   `approvals_no_self_approval`     `decided_by <> requested_by`. 13-operational-model.md:757
 *                                    says self-approval "is refused by the service, not by
 *                                    documentation"; this is the sentence under that sentence.
 *                                    The route refuses it first, with a specific message — but a
 *                                    route is code somebody edits, and this is not.
 *
 *   `approvals_execution_needs_approval`  A row may not record an execution unless it is in the
 *                                    `approved` state. An action that ran without a second pair
 *                                    of eyes is the single failure this table exists to prevent,
 *                                    and it cannot be written down.
 *
 *   `approvals_decider_is_not_the_subject`  Version 12, and the fifth. `decided_by` may not be
 *                                    the principal the row is ABOUT. The four above count
 *                                    signatures; this one is the only constraint here that asks
 *                                    who benefits. See version 12's own block, and the header of
 *                                    `src/approvals.ts`, for the hole it closes.
 *
 * ---------------------------------------------------------------------------------------------
 * **A NOTE ON VERSION 6's SD-11 CITATION, WHICH CANNOT BE CORRECTED WHERE IT STANDS — #317.**
 *
 * Version 6's SQL says "SD-11 requires an emergency freeze to be cleared by two". #317 read that,
 * together with the matching line in `src/flags.ts`, as citing a requirement nothing in the estate
 * implements — a rule named in the schema, no freeze action in `ACTIONS`, and `flags.ts` ruling
 * out the nearest mechanism. That reading is wrong, and the correction belongs here rather than
 * there for a mechanical reason: a released migration is hash-pinned by `@cloudsforge/db`, and
 * `migrations.test.ts` refuses a set in which an applied migration's text changed, so editing that
 * comment would make every existing database refuse to boot. Same rule as version 11's note about
 * version 5's column comment: read them together, newest last.
 *
 * The citation is accurate and the freeze is BUILT — in `policy/src/freezes.ts`, where
 * `REQUIRED_CLEARANCES` is 2, the same operator cannot clear twice because `freeze_clearances`
 * has `(freeze_id, operator)` as its primary key, and `DELETE /freezes/:id` answers 202 rather
 * than 200 until a second distinct operator arrives. Measured on mainnet 2026-08-10, both tables
 * exist in the estate's `policy` database and hold 0 rows: never exercised, which is what an
 * estate with no real users looks like, and not the same thing as missing. `src/flags.ts` carries
 * the longer argument for why the freeze must stay in policy and not migrate here.
 * ---------------------------------------------------------------------------------------------
 *
 *   `audit_events_source_event_uniq` The mirror's dedupe key. 17 §2 requires every service's
 *                                    audit rows to be "mirrored to admin-api", delivery is
 *                                    at-least-once, and a redelivered mirror row that appended a
 *                                    second time would break the chain's meaning: the audit of
 *                                    record would show one action twice and an operator counting
 *                                    signatures would get the wrong number.
 *
 * **AND THE COLUMNS THAT ARE NOT HERE.** There is no `balance`, no `users` table, no `listings`,
 * no copy of another service's domain rows. This service is a BFF: it composes and it audits.
 * `audit_events.subject_id` is a REFERENCE to a row somebody else owns, and it is deliberately
 * `text` rather than a uuid FK — the subject may be a ledger entry id, a market case id, an
 * account handle or an on-chain hash, and none of those live here. If a column here ever starts
 * being read as the truth about another service's state, this service has become a second copy
 * of that service and both have stopped being able to migrate.
 * ---------------------------------------------------------------------------------------------
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Taken verbatim from the runtime package so the table the claim query assumes and the table
    // that exists cannot drift.
    up: JOBS_SCHEMA_SQL,
  },
  {
    version: 2,
    name: 'outbox',
    up: `
      create table if not exists outbox (
        id             uuid        primary key default gen_random_uuid(),
        topic          text        not null,
        key            text        not null,
        occurred_at    timestamptz not null default now(),
        producer       text        not null,
        version        integer     not null default 1,
        actor          text,
        correlation_id text,
        payload        jsonb       not null default '{}'::jsonb,
        published_at   timestamptz
      );

      create index if not exists outbox_unpublished_idx
        on outbox (occurred_at)
        where published_at is null;

      create table if not exists event_subscriptions (
        id         uuid        primary key default gen_random_uuid(),
        topic      text        not null,
        url        text        not null,
        active     boolean     not null default true,
        created_at timestamptz not null default now(),
        constraint event_subscriptions_topic_url_uniq unique (topic, url)
      );

      create table if not exists outbox_deliveries (
        event_id        uuid        not null references outbox (id) on delete cascade,
        subscription_id uuid        not null references event_subscriptions (id) on delete cascade,
        delivered_at    timestamptz,
        attempts        integer     not null default 0,
        last_error      text,
        primary key (event_id, subscription_id)
      );
    `,
  },
  {
    version: 3,
    name: 'inbox',
    up: `
      -- Delivery is at-least-once, so the consumer is what makes it effectively-once. The primary
      -- key IS the dedupe. Here that matters more than usual: the inbound events this service
      -- consumes are OTHER SERVICES' AUDIT ROWS, and an audit of record that shows one privileged
      -- action twice is wrong in the direction that gets an innocent operator suspended.
      create table if not exists inbox (
        topic       text        not null,
        event_id    uuid        not null,
        received_at timestamptz not null default now(),
        primary key (topic, event_id)
      );
    `,
  },
  {
    version: 4,
    name: 'idempotency',
    // The shape is market's, which took it from the ledger, which took it from forge-pay's
    // store.ts:153. The claim INSERT and the work share ONE transaction, so the stored response
    // can never disagree with what committed. See src/idempotency.ts.
    up: `
      create table if not exists idempotency_keys (
        key          text        primary key,
        route        text        not null,
        request_hash text        not null,
        response     jsonb,
        -- What the key produced, so an operator can join a caller's key to the approval, flag
        -- change or broadcast it made. Text rather than a uuid FK: the artefact may belong to
        -- another service's table entirely.
        artefact_id  text,
        created_at   timestamptz not null default now()
      );

      create index if not exists idempotency_keys_created_idx on idempotency_keys (created_at);
    `,
  },
  {
    version: 5,
    name: 'audit_events',
    up: `
      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- THE TAMPER-EVIDENT AUDIT MIRROR.
      --
      -- SD-15: "Only a transactional, append-only, hash-chained record can" answer "who did what,
      -- to whose data, and was it allowed" months later under dispute. SD-11 requires this
      -- service to hold that record for the whole estate. SD-16 verifies chain continuity
      -- nightly and calls a break a P0.
      --
      -- Every column below the line marked HASHED is an input to \`hash\`. \`prev_hash\` is the
      -- predecessor's \`hash\`, so a row edited or removed breaks every link after it.
      --
      -- WHAT IS DELIBERATELY *NOT* HASHED: nothing. \`seq\` is allocated from the sequence by the
      -- appender BEFORE the insert so it can be hashed too, which is what makes a reordering
      -- detectable as well as an edit. There is no unhashed column on this table on purpose: a
      -- column outside the chain is a column somebody can change without leaving a mark, and the
      -- first person to add one will not think of it that way.
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists audit_events (
        seq             bigint      primary key,
        id              uuid        not null,
        -- When the action happened, as claimed by whoever recorded it. For a local operator
        -- action that is this process's clock; for a mirrored row it is the SOURCE service's,
        -- because the claim being audited is theirs and rewriting their timestamp with ours would
        -- make the mirror disagree with the original.
        occurred_at     timestamptz not null,
        -- When this service wrote it down. Distinct from occurred_at, and hashed, so the lag
        -- between an action and its mirror is itself part of the evidence.
        recorded_at     timestamptz not null,
        -- WHO. A principal — 'user:<uuid>' or 'service:<name>' — never a bare id. An operator
        -- acts as themselves: see the header of src/audit.ts for the /internal-route precedent
        -- this shape exists to avoid repeating.
        actor           text        not null,
        action          text        not null,
        subject_kind    text        not null,
        subject_id      text        not null,
        -- Mandatory from a closed list for destructive actions (13 §16). Null is legal for a
        -- read or a mirrored row whose source did not carry one.
        reason_code     text,
        outcome         text        not null,
        -- 'admin-api' for a locally originated action, otherwise the service that mirrored it.
        source          text        not null,
        -- The mirror's dedupe key. Null for a local row; unique when present.
        source_event_id uuid,
        correlation_id  text,
        payload         jsonb       not null default '{}'::jsonb,
        prev_hash       text        not null,
        hash            text        not null,

        constraint audit_events_id_uniq unique (id),
        constraint audit_events_hash_uniq unique (hash),
        constraint audit_events_source_event_uniq unique (source_event_id),
        constraint audit_events_outcome_known check (outcome in ('allowed','refused','failed')),
        constraint audit_events_actor_is_a_principal
          check (actor ~ '^(user|service):[A-Za-z0-9:._-]{1,128}$'),
        -- ══════════════════════════════════════════════════════════════════════════════════
        -- THE LINE THAT MAKES IT A CHAIN. A hash is the predecessor of at most one row, so two
        -- appenders that read the same head cannot both commit and the history cannot fork.
        -- Without it the chain verifier would still DETECT a fork after the fact; with it a fork
        -- cannot be written, which is a strictly stronger property and costs one index.
        -- ══════════════════════════════════════════════════════════════════════════════════
        constraint audit_events_chain_uniq unique (prev_hash)
      );

      -- The sequence is created explicitly rather than through bigserial: the appender calls
      -- nextval() itself so the value can be hashed before the row exists.
      create sequence if not exists audit_events_seq as bigint start with 1 increment by 1;

      create index if not exists audit_events_actor_idx on audit_events (actor, seq desc);
      create index if not exists audit_events_action_idx on audit_events (action, seq desc);
      create index if not exists audit_events_subject_idx on audit_events (subject_kind, subject_id, seq desc);
      create index if not exists audit_events_correlation_idx
        on audit_events (correlation_id) where correlation_id is not null;
      create index if not exists audit_events_occurred_idx on audit_events (occurred_at desc);

      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- WHY CHECKPOINTS EXIST, AND THE ATTACK THEY ARE THE ONLY DEFENCE AGAINST.
      --
      -- A hash chain detects an EDIT and an INTERIOR DELETION: both break a link. It does not, on
      -- its own, detect TRUNCATION — remove the last N rows and what remains is a shorter chain
      -- that verifies perfectly. That is the attack an operator covering their tracks would
      -- actually run, because it is the one that requires no forgery.
      --
      -- A checkpoint is an independent record of "the chain had reached seq S with head hash H
      -- and N events". Truncating below a checkpoint is then detectable: the checkpoint names a
      -- row that is no longer there, or a head hash that no longer matches. Removing the
      -- checkpoint too is possible — this is tamper-EVIDENT, not tamper-PROOF — but it doubles
      -- the number of tables that have to be edited consistently, and the checkpoint row is what
      -- an off-host backup and an external attestation would carry.
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists audit_chain_checkpoints (
        seq         bigint      primary key,
        hash        text        not null,
        event_count bigint      not null,
        verified_at timestamptz not null default now(),
        verified_by text        not null,
        constraint audit_chain_checkpoints_count_positive check (event_count > 0)
      );
    `,
  },
  {
    version: 6,
    name: 'approvals',
    up: `
      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- THE APPROVAL QUEUE. Two operators, or nothing happens.
      --
      -- SD-10 requires two operators and a mandatory reason code for a manual ledger adjustment;
      -- SD-11 requires an emergency freeze to be cleared by two; 13 §16 states that self-approval
      -- "is refused by the service, not by documentation".
      --
      -- The state machine is deliberately small: pending → approved | rejected | expired, and
      -- nothing leaves a terminal state. Execution is recorded ON the approved row rather than in
      -- a second table, so "was this authorised" and "did it run" cannot be answered by two rows
      -- that disagree.
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists approvals (
        id                uuid        primary key default gen_random_uuid(),
        action            text        not null,
        subject_kind      text        not null,
        subject_id        text        not null,
        params            jsonb       not null default '{}'::jsonb,
        reason_code       text        not null,
        reason            text        not null,
        requested_by      text        not null,
        requested_at      timestamptz not null default now(),
        expires_at        timestamptz not null,
        state             text        not null default 'pending',
        decided_by        text,
        decided_at        timestamptz,
        decision_note     text,
        executed_at       timestamptz,
        execution_outcome text,
        execution_detail  jsonb,
        correlation_id    text,

        constraint approvals_state_known
          check (state in ('pending','approved','rejected','expired')),
        constraint approvals_requester_is_a_principal
          check (requested_by ~ '^user:[A-Za-z0-9:._-]{1,128}$'),
        constraint approvals_reason_present check (char_length(reason) between 1 and 2000),

        -- ══════════════════════════════════════════════════════════════════════════════════
        -- FOUR EYES. The requester may not be the approver, and no route can make it otherwise.
        -- ══════════════════════════════════════════════════════════════════════════════════
        constraint approvals_no_self_approval
          check (decided_by is null or decided_by <> requested_by),

        -- A decision names the operator who took it. 'expired' is not a decision anybody took,
        -- so it carries no decider — which is exactly why it can never lead to an execution.
        constraint approvals_decision_is_attributed check (
          (state in ('approved','rejected')) = (decided_by is not null)
          and (decided_by is null) = (decided_at is null)
        ),
        constraint approvals_decider_is_a_principal
          check (decided_by is null or decided_by ~ '^user:[A-Za-z0-9:._-]{1,128}$'),

        -- ══════════════════════════════════════════════════════════════════════════════════
        -- An action that ran without a second pair of eyes cannot be written down.
        -- ══════════════════════════════════════════════════════════════════════════════════
        constraint approvals_execution_needs_approval
          check (executed_at is null or state = 'approved'),
        constraint approvals_execution_is_complete check (
          (executed_at is null) = (execution_outcome is null)
        ),
        constraint approvals_execution_outcome_known check (
          execution_outcome is null or execution_outcome in ('succeeded','failed')
        )
      );

      create index if not exists approvals_pending_idx
        on approvals (expires_at) where state = 'pending';
      create index if not exists approvals_requested_idx on approvals (requested_at desc);
      create index if not exists approvals_action_idx on approvals (action, requested_at desc);
    `,
  },
  {
    version: 7,
    name: 'flags_and_broadcasts',
    up: `
      -- 17 §1 row 8: a feature flag ships "with the default stated and the owner named". Both are
      -- NOT NULL here, so a flag nobody owns cannot be created — which is the flag that is still
      -- switched off two years later with the revenue line behind it (17 §9, Crucible).
      create table if not exists feature_flags (
        key         text        primary key,
        enabled     boolean     not null,
        description text        not null,
        owner       text        not null,
        created_at  timestamptz not null default now(),
        updated_at  timestamptz not null default now(),
        updated_by  text        not null,
        constraint feature_flags_key_shape check (key ~ '^[a-z][a-z0-9_.-]{1,62}[a-z0-9]$'),
        constraint feature_flags_owner_named check (char_length(owner) between 1 and 200),
        constraint feature_flags_described check (char_length(description) between 1 and 2000)
      );

      -- 13 §11: scheduled maintenance and incident notices reach the public status page as
      -- "admin-api broadcasts". A retraction is a new state on the same row rather than a DELETE,
      -- because "what did we tell users during the incident" is a question asked afterwards.
      create table if not exists broadcasts (
        id           uuid        primary key default gen_random_uuid(),
        severity     text        not null,
        title        text        not null,
        body         text        not null,
        starts_at    timestamptz not null default now(),
        ends_at      timestamptz,
        published_by text        not null,
        published_at timestamptz not null default now(),
        retracted_at timestamptz,
        retracted_by text,
        constraint broadcasts_severity_known
          check (severity in ('info','maintenance','incident')),
        constraint broadcasts_title_length check (char_length(title) between 1 and 200),
        constraint broadcasts_body_length check (char_length(body) between 1 and 5000),
        constraint broadcasts_window_ordered check (ends_at is null or ends_at > starts_at),
        constraint broadcasts_retraction_is_attributed
          check ((retracted_at is null) = (retracted_by is null))
      );

      create index if not exists broadcasts_live_idx on broadcasts (starts_at desc)
        where retracted_at is null;
    `,
  },
  {
    version: 8,
    name: 'engagement',
    up: `
      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- THE ENGAGEMENT TREASURY'S CAPS — docs/ecosystem/21 §4 and §8.
      --
      -- §8's build order is law: "nothing may move before the caps exist." So the caps are rows
      -- with CHECK constraints, the transfers that spend against them are rows a trigger refuses
      -- above the cap, and both hold against a caller with a database connection — which is the
      -- caller every route-level check is helpless against.
      --
      -- WHAT THIS IS NOT: a balance. The Shards live in micro-ledger accounts
      -- ('platform:engagement-treasury' and 'engagement:<service>' — the grammar is
      -- contracts/packages/money/src/index.ts, the accounts ordinary rows in the ledger's chart).
      -- This service holds the OPERATOR STATE about them: what an operator may move, and the
      -- record that each approved movement produced exactly one ledger entry. An auditor
      -- reconstructs the programme from the ledger alone (21 §4); these tables are how the
      -- operator surface refuses to let that reconstruction ever show more than the caps allowed.
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists engagement_policies (
        -- The six rooms 21 §1 names. A closed list, because a policy row for a service nobody
        -- decided to seed is a cap nobody decided to grant.
        service                 text        primary key,
        -- The most one APPROVED transfer may move into this service's engagement account.
        -- bigint Shards: at 100 Shards/USD (contracts-chain SHARDS_PER_USD) the ceiling below is
        -- USD 10,000,000 per transfer — deliberately far above any sane early-programme value and
        -- deliberately finite, because "no ceiling" is how devplatform's quota defect happened.
        transfer_cap_shards     bigint      not null default 0,
        -- Foresight's house-seed sizes (21 §5), EMBER wei per outcome side and per UTC day —
        -- wei because the seed is an on-chain stake and the pool it discloses into is wei.
        -- numeric(78,0): any uint256, exact. micro-foresight pins the SAME ceilings in its own
        -- schema (foresight/src/migrations.ts version 8) so the bound holds in both databases.
        seed_per_market_wei     numeric(78,0),
        seed_per_day_wei        numeric(78,0),
        -- The approval that last RAISED anything here. The trigger below refuses a raise that
        -- does not name a fresh approved 'engagement.policy.set' approval; lowering needs none —
        -- the devplatform asymmetry (devplatform/src/server.ts:981 'THE DIRECTION IS THE
        -- AUTHORITY'), enforced in the schema rather than restated in a route.
        last_change_approval_id uuid        references approvals (id),
        updated_at              timestamptz not null default now(),
        updated_by              text        not null,

        constraint engagement_policies_service_known check (
          service in ('foresight','market','worlds','aetherholm','emberkin','trade')
        ),
        -- 1,000,000,000 Shards = USD 10M/transfer. The ceiling on the CAP, not the cap: an
        -- operator sets any value at or below this; nothing sets one above it.
        constraint engagement_policies_cap_within_ceiling check (
          transfer_cap_shards >= 0 and transfer_cap_shards <= 1000000000
        ),
        -- Seed sizes are foresight's alone (21 §5 gives the house seed to foresight; every other
        -- service spends through grants, never stakes).
        constraint engagement_policies_seeds_are_foresights check (
          (seed_per_market_wei is null and seed_per_day_wei is null) or service = 'foresight'
        ),
        -- Half a seed policy is not a policy: a per-market size with no per-day bound is exactly
        -- the unbounded spend 21 §7.3 exists to refuse.
        constraint engagement_policies_seed_pair check (
          (seed_per_market_wei is null) = (seed_per_day_wei is null)
        ),
        -- Ceilings: 1e21 wei = 1,000 EMBER per market side; 1e22 wei = 10,000 EMBER per day.
        -- A per-day value below the per-market value would make every seeded market refuse, so
        -- the nonsense is refused at the write instead.
        constraint engagement_policies_seed_within_ceiling check (
          seed_per_market_wei is null or (
            seed_per_market_wei > 0
            and seed_per_market_wei <= 1000000000000000000000
            and seed_per_day_wei >= seed_per_market_wei
            and seed_per_day_wei <= 10000000000000000000000
          )
        )
      );

      -- The fee recycle (21 §3): a configured share of platform fee revenue posts to the
      -- treasury each period. One row, because it is one platform-wide number. Seeded at 0 —
      -- 21's closing 'open decision' recommends starting at pure mined funding, and raising it
      -- later already requires the approval-gated action.
      create table if not exists engagement_fee_recycle (
        singleton               boolean     primary key default true,
        recycle_bps             integer     not null default 0,
        last_change_approval_id uuid        references approvals (id),
        updated_at              timestamptz not null default now(),
        updated_by              text        not null,

        constraint engagement_fee_recycle_one_row check (singleton),
        -- 2500 bps = 25%. A recycle above a quarter of fee revenue is an engagement programme
        -- eating the business that funds it; 21 §7.5 requires the ceiling to be schema, and this
        -- is it.
        constraint engagement_fee_recycle_within_ceiling check (
          recycle_bps >= 0 and recycle_bps <= 2500
        )
      );
      insert into engagement_fee_recycle (singleton, recycle_bps, updated_by)
      values (true, 0, 'migration:8')
      on conflict (singleton) do nothing;

      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- RAISING NEEDS TWO OPERATORS; LOWERING NEEDS NONE. 21 §7.7, as a trigger.
      --
      -- A raise must name a FRESH approval row that two operators drove to 'approved' for
      -- exactly this action. The route enforces the same thing first with a readable sentence;
      -- this is what holds when the write arrives by any other door. Freshness (the approval id
      -- must CHANGE on a raise) is what stops one approval authorising unlimited later raises.
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create or replace function engagement_raise_needs_approval() returns trigger
        language plpgsql
      as $$
      declare
        raised boolean;
        approved boolean;
      begin
        if tg_table_name = 'engagement_policies' then
          if tg_op = 'INSERT' then
            raised := new.transfer_cap_shards > 0 or new.seed_per_market_wei is not null;
          else
            raised := new.transfer_cap_shards > old.transfer_cap_shards
              or (new.seed_per_market_wei is not null and (old.seed_per_market_wei is null or new.seed_per_market_wei > old.seed_per_market_wei))
              or (new.seed_per_day_wei is not null and (old.seed_per_day_wei is null or new.seed_per_day_wei > old.seed_per_day_wei));
          end if;
        else
          if tg_op = 'INSERT' then
            raised := new.recycle_bps > 0;
          else
            raised := new.recycle_bps > old.recycle_bps;
          end if;
        end if;

        if not raised then
          return new;
        end if;

        if new.last_change_approval_id is null
           or (tg_op = 'UPDATE' and new.last_change_approval_id is not distinct from old.last_change_approval_id) then
          raise exception 'raising an engagement cap requires a fresh approved engagement.policy.set approval; lowering does not (21 §7.7)'
            using errcode = 'check_violation';
        end if;

        select (state = 'approved' and action = 'engagement.policy.set')
          into approved
          from approvals where id = new.last_change_approval_id;
        if approved is distinct from true then
          raise exception 'approval % is not an approved engagement.policy.set approval', new.last_change_approval_id
            using errcode = 'check_violation';
        end if;
        return new;
      end;
      $$;

      drop trigger if exists engagement_policies_raise_needs_approval on engagement_policies;
      create trigger engagement_policies_raise_needs_approval
        before insert or update on engagement_policies
        for each row execute function engagement_raise_needs_approval();

      drop trigger if exists engagement_fee_recycle_raise_needs_approval on engagement_fee_recycle;
      create trigger engagement_fee_recycle_raise_needs_approval
        before insert or update on engagement_fee_recycle
        for each row execute function engagement_raise_needs_approval();

      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- THE TRANSFER RECORD. One row per approved treasury → service movement, and the row IS
      -- where the cap binds (21 §7.3): the trigger refuses an amount above the service's policy
      -- cap, refuses a service with no policy row at all ("the caps must exist before a Shard
      -- moves"), and refuses an approval that is not an approved engagement.transfer.
      --
      -- 21 §7.4, the pairing: 'posted' and a ledger entry id are one fact
      -- (engagement_transfers_posted_names_entry), and one approval is one transfer for ever
      -- (engagement_transfers_one_per_approval) — the same key the ledger idempotency key is
      -- derived from, so a retry replays rather than moving twice.
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists engagement_transfers (
        id              uuid        primary key default gen_random_uuid(),
        service         text        not null references engagement_policies (service),
        amount_shards   bigint      not null,
        approval_id     uuid        not null references approvals (id),
        -- The ledger's entry id, once posted. text, like audit_events.subject_id: it is a
        -- REFERENCE to a row another service owns.
        ledger_entry_id text,
        state           text        not null default 'posting',
        created_at      timestamptz not null default now(),
        posted_at       timestamptz,

        constraint engagement_transfers_amount_positive check (amount_shards > 0),
        constraint engagement_transfers_one_per_approval unique (approval_id),
        constraint engagement_transfers_state_known check (state in ('posting','posted')),
        constraint engagement_transfers_posted_names_entry check (
          ((state = 'posted') = (ledger_entry_id is not null))
          and ((state = 'posted') = (posted_at is not null))
        )
      );

      create index if not exists engagement_transfers_service_idx
        on engagement_transfers (service, created_at desc);

      create or replace function engagement_transfer_within_cap() returns trigger
        language plpgsql
      as $$
      declare
        cap bigint;
        ok boolean;
      begin
        select transfer_cap_shards into cap from engagement_policies where service = new.service;
        if cap is null then
          raise exception 'no engagement policy exists for %; the caps must exist before a Shard moves (21 §8)', new.service
            using errcode = 'check_violation';
        end if;
        if new.amount_shards > cap then
          raise exception 'transfer of % Shards to engagement:% exceeds the policy cap of % (21 §7.3)',
            new.amount_shards, new.service, cap
            using errcode = 'check_violation';
        end if;
        select (state = 'approved' and action = 'engagement.transfer')
          into ok
          from approvals where id = new.approval_id;
        if ok is distinct from true then
          raise exception 'approval % is not an approved engagement.transfer approval', new.approval_id
            using errcode = 'check_violation';
        end if;
        return new;
      end;
      $$;

      drop trigger if exists engagement_transfers_within_cap on engagement_transfers;
      create trigger engagement_transfers_within_cap
        before insert on engagement_transfers
        for each row execute function engagement_transfer_within_cap();
    `,
  },

  {
    version: 9,
    name: 'erasure-register',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- THE ERASURE REGISTER, AND WHY THE AUDIT LOG ITSELF IS NOT TOUCHED.
      --
      -- The full argument, with the Article numbers, is the header of \`src/erasure.ts\`. The short
      -- form: \`audit_events\` is a hash chain over \`subject_id\` and \`payload\` among other
      -- columns, so rewriting either invalidates that row's hash and every hash after it. An audit
      -- trail exists so that it cannot be edited by the person it records, and the subject of an
      -- admin action is frequently the person with the strongest motive to edit it. The rows are
      -- RETAINED under Art. 17(3)(b) — AML/CTF record-keeping — and 17(3)(e) — defence of legal
      -- claims — and withheld from every read surface under Art. 18 instead.
      --
      -- This table is what makes that withholding possible, and what makes the retention
      -- defensible: Art. 5(2) requires us to be able to DEMONSTRATE compliance, and "we kept it
      -- under 17(3)" is not demonstrable without a record of who asked and when.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      create table if not exists audit_subject_erasures (
        subject_kind    text        not null,
        subject_id      text        not null,
        -- The event that requested it. Unique, so a redelivery cannot register a second erasure
        -- and a register entry can always be traced back to the delivery that caused it.
        source_event_id uuid        not null,
        -- identity's deadline, carried on the event so we do not have to know its configuration.
        tombstone_at    timestamptz,
        reason          text,
        erased_at       timestamptz not null default now(),

        constraint audit_subject_erasures_pk primary key (subject_kind, subject_id),
        constraint audit_subject_erasures_event_uniq unique (source_event_id),

        -- ══════════════════════════════════════════════════════════════════════════════════
        -- ONLY A USER MAY BE ERASED, AND THE DATABASE IS WHAT SAYS SO.
        --
        -- \`audit_events.subject_id\` is deliberately \`text\` rather than a uuid, because the
        -- subject may be a ledger entry id, a market case id, an account handle or an on-chain
        -- hash (migrations.ts:39-40). Only a subject that IS a person is in scope for erasure.
        --
        -- Without this, a register row naming a ledger entry would silently restrict — from every
        -- operator read, during an incident — an audit row about a movement of money that no
        -- data subject ever asked about, and nothing would look wrong. The handler filters on
        -- \`subject_kind\` too; this is the half that survives somebody editing the handler.
        -- ══════════════════════════════════════════════════════════════════════════════════
        constraint audit_subject_erasures_user_only check (subject_kind = 'user')
      );

      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- AN ERASURE, ONCE REGISTERED, CANNOT BE WITHDRAWN.
      --
      -- Every restriction on the read path is derived from this table, so a DELETE here silently
      -- un-restricts every audit row about that person and re-exposes their subject id and the
      -- mirrored payloads beside it. An UPDATE that changed \`subject_id\` would do the same to one
      -- person while restricting an unrelated one.
      --
      -- There is no legitimate caller for either. An erasure is a fact about something that
      -- happened; it is not configuration. Registering the same subject twice is already handled
      -- by \`on conflict do nothing\` in the handler, which needs no UPDATE.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      create or replace function audit_erasure_register_is_final() returns trigger
        language plpgsql
      as $$
      begin
        raise exception
          'the erasure register is append-only; an erasure cannot be withdrawn or re-pointed'
          using errcode = 'check_violation';
      end;
      $$;

      drop trigger if exists audit_subject_erasures_immutable on audit_subject_erasures;
      create trigger audit_subject_erasures_immutable
        before update or delete on audit_subject_erasures
        for each row execute function audit_erasure_register_is_final();

      -- Erasure de-links the subject of a four-eyes approval — that table is NOT hash-chained, so
      -- it can be genuinely anonymised rather than merely restricted. The lookup is on both
      -- columns, because matching \`subject_id\` alone would rewrite an approval about a ledger
      -- entry that happens to share the uuid.
      create index if not exists approvals_subject_idx on approvals (subject_kind, subject_id);
    `,
  },

  {
    version: 10,
    name: 'backups',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- BACKUP AND RESTORE. The control plane only: this service NEVER touches a dump file.
      --
      -- WHAT THIS SERVICE OWNS: the catalogue, the authority to start a run, the environment
      -- invariant, and the audit row. WHAT IT DOES NOT OWN: the bytes. Rule 1 gives this service
      -- exactly one database and CI greps the source for a second DSN, so a process that dumps
      -- twenty-nine OTHER databases cannot live in \`admin-api/src\` — and should not, because
      -- reading every database in the cluster is a different trust domain from composing an
      -- operator's console. The data plane is \`deploy/backup\`, a separate deployable that leases
      -- \`backup.*\` jobs out of the table below. \`JobRunner.claim()\` filters by REGISTERED kind
      -- (runtime/packages/jobs/src/index.ts:380), so this service enqueues work it will never
      -- claim, and the runner claims work nothing else will take. One queue, two processes, no
      -- handler collision — and if no runner is deployed the rows sit \`queued\` and the console
      -- says so, which is honest rather than silent.
      --
      -- ── THE THREE INVARIANTS, IN THE SCHEMA, BECAUSE A ROUTE IS WHAT AN ATTACKER GETS PAST ──
      --
      --   \`estate_identity_is_immutable\`      An estate says which environment it is EXACTLY
      --                                        ONCE, and can never say anything else.
      --   \`restore_runs_environment_matches\`  A restore whose backup was taken in another
      --                                        environment cannot be written down.
      --   \`restore_runs_live_needs_approval\`  A restore that overwrites live data cannot exist
      --                                        without an approval two operators signed.
      -- ════════════════════════════════════════════════════════════════════════════════════════

      -- ── ARTEFACT OF IDENTITY. The fact a restore is checked against.
      --
      -- 2026-08-05, twice: the seeder ran \`docker compose\` against the MAINNET project whatever
      -- the target was, so a testnet action recreated a mainnet container. A restore with that bug
      -- overwrites real balances with test ones. The defence cannot be a parameter — the bug WAS a
      -- parameter that was ignored — so it is this row: written once at first boot from
      -- ADMIN_API_ESTATE_ENVIRONMENT, immutable thereafter, and compared against the environment
      -- recorded INSIDE the backup artefact. Both sides self-identify and neither is passed in.
      --
      -- The service refuses to start when its configured environment disagrees with this row
      -- (src/index.ts), which is what turns a mis-pointed compose file into a container that will
      -- not boot instead of a restore into the wrong estate.
      create table if not exists estate_identity (
        singleton   boolean     primary key default true,
        environment text        not null,
        claimed_at  timestamptz not null default now(),
        claimed_by  text        not null,
        constraint estate_identity_one_row check (singleton),
        constraint estate_identity_known
          check (environment in ('mainnet','testnet','development'))
      );

      -- An estate's identity is a fact about which estate this IS, not configuration. Allowing an
      -- UPDATE would let a compose file edit re-label mainnet as testnet and thereby unlock exactly
      -- the restore this table exists to refuse. There is no legitimate caller: an estate that is
      -- genuinely a different estate has a different database.
      create or replace function estate_identity_is_final() returns trigger
        language plpgsql
      as $$
      begin
        raise exception
          'the estate identity is claimed once and cannot be changed (it is what a restore is checked against)'
          using errcode = 'check_violation';
      end;
      $$;

      drop trigger if exists estate_identity_immutable on estate_identity;
      create trigger estate_identity_immutable
        before update or delete on estate_identity
        for each row execute function estate_identity_is_final();

      -- ── SETTINGS. One row. The destination is configurable from the panel because the owner
      -- asked for it; every bound on it is a CHECK because "configurable" must not mean
      -- "unbounded". Filling the destination disk on this host stops the miner and the chain.
      create table if not exists backup_settings (
        singleton              boolean     primary key default true,
        -- The default is the second physical disk (/dev/sdb1, 1.4 TB free), mounted at /data on
        -- the host and bound to /backups in the runner. It is a DIFFERENT SPINDLE from the one
        -- holding the databases, which is the whole point: backups beside the thing they back up
        -- die with it. See docs for what this does and does not protect against.
        root_path              text        not null default '/backups',
        -- How many complete backup sets to keep. The prune job removes the oldest beyond this.
        retention_copies       integer     not null default 14,
        -- The hard ceiling. The runner refuses to START a run that could exceed it, and the prune
        -- job enforces it after. 200 GiB against 1.4 TB free leaves the chain its headroom with an
        -- order of magnitude to spare.
        ceiling_bytes          bigint      not null default 214748364800,
        -- Refuse to write when the destination filesystem has less than this free, whatever the
        -- ceiling says. A ceiling protects the disk from THIS system; this protects it from
        -- everything else that shares the disk.
        min_free_bytes         bigint      not null default 107374182400,
        schedule_enabled       boolean     not null default true,
        schedule_every_minutes integer     not null default 1440,
        -- Periodic self-verification: restore the newest backup into a scratch database and report.
        -- A backup that silently stopped working looks exactly like one that works.
        verify_enabled         boolean     not null default true,
        verify_every_minutes   integer     not null default 1440,
        updated_at             timestamptz not null default now(),
        updated_by             text        not null default 'migration:10',

        constraint backup_settings_one_row check (singleton),
        -- Absolute, no traversal, no shell metacharacters. This string becomes a path in a process
        -- that runs tar and pg_restore; a route validates it too, and this is what holds when the
        -- write arrives by another door.
        constraint backup_settings_root_is_absolute
          check (root_path ~ '^/[A-Za-z0-9._/-]{0,255}$' and root_path !~ '\\.\\.'),
        constraint backup_settings_retention_sane
          check (retention_copies between 1 and 365),
        -- Floor 1 GiB: a ceiling below one backup set means every run fails. Roof 1 TiB: below the
        -- 1.4 TB free, so the setting cannot be used to fill the disk that holds the chain.
        constraint backup_settings_ceiling_sane
          check (ceiling_bytes between 1073741824 and 1099511627776),
        constraint backup_settings_headroom_sane
          check (min_free_bytes between 1073741824 and 1099511627776),
        constraint backup_settings_schedule_sane
          check (schedule_every_minutes between 15 and 43200),
        constraint backup_settings_verify_sane
          check (verify_every_minutes between 60 and 43200)
      );
      insert into backup_settings (singleton, updated_by) values (true, 'migration:10')
        on conflict (singleton) do nothing;

      -- ── THE RUNS.
      create table if not exists backup_runs (
        id                    uuid        primary key default gen_random_uuid(),
        -- THE MARKER. Copied into MANIFEST.json on disk, and the artefact is what a restore is
        -- checked against — not this row, which a restoring host may not even have.
        environment           text        not null,
        compose_project       text        not null,
        kind                  text        not null default 'full',
        state                 text        not null default 'queued',
        -- 'user:<uuid>' for an operator, 'service:admin-api' for the scheduled run. A backup
        -- nobody asked for is still a backup somebody is accountable for.
        requested_by          text        not null,
        reason                text,
        root_path             text        not null,
        -- <root>/<environment>/<stamp>. Null until the runner claims the row and creates it.
        directory             text,
        queued_at             timestamptz not null default now(),
        started_at            timestamptz,
        finished_at           timestamptz,
        total_bytes           bigint,
        artefact_count        integer,
        -- The checksum OF THE MANIFEST, which itself carries a checksum per artefact. One value
        -- that commits to every byte of the set.
        manifest_sha256       text,
        -- pg_control's system identifier: a fact about the cluster, generated at initdb and
        -- unique to it. Distinguishes "restore into the same cluster" from "restore into a rebuilt
        -- one", which are different operations with different risks.
        cluster_system_id     text,
        -- Whether the custody VAULT (ciphertext) is in this set. The KEYRING never is, and there
        -- is deliberately no column that could ever say it was. See src/backups.ts.
        includes_custody      boolean     not null default false,
        -- ══════════════════════════════════════════════════════════════════════════════════════
        -- WHETHER THE MINER COINBASE KEYS ARE IN THIS SET — AS CIPHERTEXT, ALWAYS.
        --
        -- The Hearth miners hold their reward key natively, in PLAINTEXT, in a 240-byte JSON file
        -- at mode 0600 on one disk, with no backup and no rotation path. The mainnet coinbase
        -- 0x980d…5b45 held 9,332 EMBER of genuinely mined coin when this was written. Losing that
        -- file loses that money exactly as losing a custody blob does, and it is the single most
        -- valuable unprotected artefact on the host.
        --
        -- So it is backed up — and it is encrypted BEFORE it is written, to an age recipient whose
        -- private half never exists on this machine. That is the difference between fixing
        -- durability and creating a disclosure: an unencrypted key copied to a second disk in the
        -- same room is a second place to steal it from.
        --
        -- This column exists so the console can say a key backup EXISTS without ever showing what
        -- is in it, and so an operator can see at a glance which sets would need the offline
        -- identity to recover fully.
        -- ══════════════════════════════════════════════════════════════════════════════════════
        includes_secrets      boolean     not null default false,
        error                 text,
        correlation_id        text,
        -- The last time a restore of THIS set was actually proven to work, and by which run.
        -- Null means: nobody has ever restored this. A backup nobody has restored is a wish.
        verified_at           timestamptz,
        verified_by_restore   uuid,

        constraint backup_runs_environment_known
          check (environment in ('mainnet','testnet','development')),
        constraint backup_runs_kind_known
          check (kind in ('full','databases','custody','files')),
        constraint backup_runs_state_known
          check (state in ('queued','running','succeeded','failed','pruned')),
        constraint backup_runs_requester_is_a_principal
          check (requested_by ~ '^(user|service):[A-Za-z0-9:._-]{1,128}$'),

        -- ══════════════════════════════════════════════════════════════════════════════════════
        -- A SUCCEEDED BACKUP HAS A CHECKSUM, OR IT IS NOT SUCCEEDED.
        --
        -- "A backup whose integrity is unverified is a guess." The state and the evidence for it
        -- are one fact, so they are one constraint; a run that finished but hashed nothing cannot
        -- be written down as a success, and the console can therefore trust the word.
        -- ══════════════════════════════════════════════════════════════════════════════════════
        constraint backup_runs_success_is_evidenced check (
          (state = 'succeeded') =
            (manifest_sha256 is not null and directory is not null
             and total_bytes is not null and artefact_count is not null)
        ),
        constraint backup_runs_failure_is_explained
          check ((state = 'failed') = (error is not null)),
        constraint backup_runs_terminal_is_finished check (
          (state in ('succeeded','failed')) = (finished_at is not null)
        ),
        -- Verification names the restore that proved it. "Verified" with nothing to point at is
        -- the reassuring green tick this whole exercise exists to refuse.
        constraint backup_runs_verification_is_attributed
          check ((verified_at is null) = (verified_by_restore is null))
      );

      create index if not exists backup_runs_recent_idx
        on backup_runs (environment, queued_at desc);
      create index if not exists backup_runs_live_idx
        on backup_runs (state, queued_at desc) where state in ('queued','running');

      -- ── ONE ROW PER FILE. The checksum lives here as well as in the manifest on disk, so an
      -- operator can be told "this file no longer hashes to what we wrote" without the artefact
      -- being present, and so a tampered manifest disagrees with the database rather than with
      -- itself.
      create table if not exists backup_artefacts (
        id           uuid        primary key default gen_random_uuid(),
        run_id       uuid        not null references backup_runs (id) on delete cascade,
        kind         text        not null,
        -- The database name, the volume name, or the file-set name.
        name         text        not null,
        -- Relative to the run's directory. Never absolute: an absolute path in a manifest is a
        -- write primitive pointed anywhere on the restoring host.
        rel_path     text        not null,
        bytes        bigint      not null,
        sha256       text        not null,
        -- Rows for a database, files for a tarball. The count a restore is checked against.
        entry_count  bigint,
        -- ══════════════════════════════════════════════════════════════════════════════════════
        -- A SECRETS ARTEFACT CARRIES A PUBLIC ADDRESS AND NOTHING ELSE IDENTIFYING.
        --
        -- \`public_ref\` is how a restore is verified without decrypting: re-derive the address from
        -- the recovered key and compare it to this. Address equality proves the recovered
        -- plaintext is genuinely the spending key for that address, and proves it while printing
        -- nothing secret — which is the same verification \`custody-backup-restore.md\` §5.3 uses.
        --
        -- The CHECK is what stops this column ever becoming a place somebody puts the key. An
        -- 0x-prefixed 40-hex address is 42 characters; a secp256k1 private key is 64 hex. The
        -- shape refuses the second.
        -- ══════════════════════════════════════════════════════════════════════════════════════
        public_ref   text,
        created_at   timestamptz not null default now(),

        -- 'secrets' is key material and is the ONLY kind written to disk already encrypted, to a
        -- recipient whose private half never touches this machine. See \`includes_secrets\` on
        -- backup_runs and the header of src/backups.ts.
        constraint backup_artefacts_kind_known
          check (kind in ('database','vault','files','secrets')),
        constraint backup_artefacts_public_ref_is_an_address
          check (public_ref is null or public_ref ~ '^0x[0-9a-fA-F]{40}$'),
        constraint backup_artefacts_secrets_name_their_address
          check (kind <> 'secrets' or public_ref is not null),
        constraint backup_artefacts_one_per_name unique (run_id, kind, name),
        constraint backup_artefacts_bytes_positive check (bytes > 0),
        constraint backup_artefacts_sha256_shape check (sha256 ~ '^[0-9a-f]{64}$'),
        constraint backup_artefacts_rel_path_is_relative
          check (rel_path ~ '^[A-Za-z0-9._/-]{1,255}$' and rel_path !~ '\\.\\.' and left(rel_path, 1) <> '/')
      );

      create index if not exists backup_artefacts_run_idx on backup_artefacts (run_id, kind, name);

      -- ── THE DANGEROUS HALF.
      create table if not exists restore_runs (
        id                 uuid        primary key default gen_random_uuid(),
        backup_run_id      uuid        not null references backup_runs (id),
        -- Copied from the backup at insert by the trigger below rather than supplied. A column the
        -- caller fills is a column the caller can lie in.
        environment        text        not null,
        -- 'verify'  restore into a scratch database, drop it afterwards. Non-destructive, always
        --           allowed, and the ONLY mode the periodic self-check uses.
        -- 'live'    overwrite the real database. Needs an approval two operators signed.
        mode               text        not null,
        -- Which artefacts. A restore that silently did more than it named is the failure this
        -- column exists to prevent.
        targets            jsonb       not null default '[]'::jsonb,
        state              text        not null default 'queued',
        requested_by       text        not null,
        reason             text,
        -- The approval two operators drove to 'approved'. NULL is legal only for mode='verify'.
        approval_id        uuid        references approvals (id),
        -- Exactly what the operator typed, kept as evidence of what they were shown and agreed to.
        confirmation       text,
        queued_at          timestamptz not null default now(),
        started_at         timestamptz,
        finished_at        timestamptz,
        -- What the runner found when it opened the artefact. The restore stops if either
        -- disagrees with the backup row — the artefact is the authority, not this table.
        artefact_environment text,
        checksums_verified   boolean,
        -- Per-target outcome: rows restored, addresses re-derived, and so on. Never key material.
        outcome            jsonb       not null default '{}'::jsonb,
        error              text,
        correlation_id     text,

        constraint restore_runs_mode_known check (mode in ('verify','live')),
        constraint restore_runs_state_known
          check (state in ('queued','running','succeeded','failed','refused')),
        constraint restore_runs_requester_is_a_principal
          check (requested_by ~ '^(user|service):[A-Za-z0-9:._-]{1,128}$'),
        constraint restore_runs_failure_is_explained
          check ((state in ('failed','refused')) = (error is not null)),
        constraint restore_runs_terminal_is_finished check (
          (state in ('succeeded','failed','refused')) = (finished_at is not null)
        ),

        -- ══════════════════════════════════════════════════════════════════════════════════════
        -- A LIVE RESTORE CANNOT EXIST WITHOUT TWO OPERATORS AND A TYPED CONFIRMATION.
        --
        -- "A restore must never be a single click. It overwrites live money data." The route asks
        -- for the typed phrase and refuses without it, with a readable sentence. This is the half
        -- that holds when the write arrives by any other door — including psql.
        --
        -- \`verify\` needs neither, and that asymmetry is the point: the safe operation must be
        -- cheap or nobody will ever run it, and a system whose only restore is terrifying is a
        -- system whose restores are never rehearsed.
        -- ══════════════════════════════════════════════════════════════════════════════════════
        constraint restore_runs_live_is_confirmed check (
          mode <> 'live' or (approval_id is not null and confirmation is not null)
        ),
        constraint restore_runs_verify_is_unapproved check (
          mode <> 'verify' or approval_id is null
        )
      );

      create index if not exists restore_runs_recent_idx on restore_runs (queued_at desc);
      create index if not exists restore_runs_backup_idx on restore_runs (backup_run_id, queued_at desc);

      -- ══════════════════════════════════════════════════════════════════════════════════════════
      -- THE ENVIRONMENT REFUSAL, AND WHY IT IS A TRIGGER AND NOT A CHECK.
      --
      -- A CHECK sees one row. The fact that decides this lives in three places — the backup's
      -- environment, THIS estate's claimed identity, and (for a live restore) the approval that
      -- authorised it — so it needs a trigger that can read them.
      --
      -- What it enforces, in order:
      --
      --   1. \`environment\` is COPIED from the backup, never accepted from the caller. This is the
      --      2026-08-05 defect in schema form: the seeder took a target parameter and ignored it,
      --      so the parameter was never the safe thing to trust.
      --   2. The backup's environment must equal THIS estate's claimed identity. A testnet backup
      --      cannot be restored into mainnet, by anyone, through any route, for any reason. There
      --      is no override flag and adding one would defeat the entire control.
      --   3. A live restore must name an approval that is APPROVED and is for this exact backup.
      --      An approval for a different backup is not consent to restore this one.
      --   4. The backup must have SUCCEEDED. Restoring from a failed run is restoring from a
      --      partial set, which is worse than not restoring: it half-overwrites live data.
      -- ══════════════════════════════════════════════════════════════════════════════════════════
      create or replace function restore_runs_environment_matches() returns trigger
        language plpgsql
      as $$
      declare
        backup_env  text;
        backup_state text;
        estate_env  text;
        appr        record;
      begin
        select environment, state into backup_env, backup_state
          from backup_runs where id = new.backup_run_id;
        if backup_env is null then
          raise exception 'no backup run %', new.backup_run_id using errcode = 'check_violation';
        end if;

        -- (4) A partial set is not a restore source.
        if backup_state <> 'succeeded' then
          raise exception
            'backup % is in state %, not succeeded — restoring from an incomplete set half-overwrites live data',
            new.backup_run_id, backup_state using errcode = 'check_violation';
        end if;

        -- (1) Derived, never accepted.
        new.environment := backup_env;

        select environment into estate_env from estate_identity where singleton;
        if estate_env is null then
          raise exception
            'this estate has not claimed an identity; a restore cannot be checked for environment confusion'
            using errcode = 'check_violation';
        end if;

        -- (2) THE REFUSAL.
        if backup_env <> estate_env then
          raise exception
            'REFUSED: that backup was taken in the % estate and this is the % estate — a cross-environment restore destroys real balances',
            backup_env, estate_env using errcode = 'check_violation';
        end if;

        -- (3) Live means two operators, for THIS backup.
        if new.mode = 'live' then
          select state, action, subject_id into appr from approvals where id = new.approval_id;
          if appr.state is distinct from 'approved' or appr.action is distinct from 'estate.restore' then
            raise exception 'approval % is not an approved estate.restore approval', new.approval_id
              using errcode = 'check_violation';
          end if;
          if appr.subject_id is distinct from new.backup_run_id::text then
            raise exception
              'approval % authorises restoring backup %, not backup % — an approval is consent to one restore',
              new.approval_id, appr.subject_id, new.backup_run_id using errcode = 'check_violation';
          end if;
        end if;

        return new;
      end;
      $$;

      drop trigger if exists restore_runs_environment_guard on restore_runs;
      create trigger restore_runs_environment_guard
        before insert on restore_runs
        for each row execute function restore_runs_environment_matches();

      -- One live restore of one backup, for ever. The same reason
      -- \`engagement_transfers_one_per_approval\` exists: an approval authorises ONE act, and a
      -- retry must replay rather than overwrite live data a second time.
      create unique index if not exists restore_runs_one_live_per_approval
        on restore_runs (approval_id) where approval_id is not null;
    `,
  },

  {
    version: 11,
    name: 'actor-kinds',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- THE MIRROR WAS NARROWER THAN THE CONTRACT IT MIRRORS. micro-org#265.
      --
      -- Version 5 wrote \`audit_events_actor_is_a_principal\` as
      --
      --     check (actor ~ '^(user|service):[A-Za-z0-9:._-]{1,128}$')
      --
      -- against the two kinds THIS service originates. It was then reused unchanged for the rows
      -- this service MIRRORS, which come from the whole estate, and the estate has four:
      -- \`ActorKind\` in contracts/packages/events/src/index.ts:70 is
      -- 'user' | 'service' | 'operator' | 'system', and \`parseActor\` beside it admits the BARE
      -- string 'system' with no subject at all.
      --
      -- Nothing converted between the two. \`auditRowFor\` takes the envelope's actor verbatim
      -- (contracts/packages/events/src/audit.ts:434) and POST /v1/events passes it straight into
      -- the insert (src/server.ts:777), so a legal envelope met a CHECK that refused it, the route
      -- answered 500 because there is no branch for "the database disagrees with the contract",
      -- and the producer's relay read that as transient and retried until its breaker opened.
      --
      -- MEASURED ON MAINNET, 2026-08-08, while verifying the 2.5.5 deploy: ledger had emitted 863
      -- \`ledger.reconciliation.completed\` — a leased job with no actor, so ledger/src/outbox.ts:201
      -- substitutes 'system' — and 10 \`ledger.entry.posted\` carrying 'operator:drift-correction'.
      -- Both topics are \`audited: true\`. \`audit_events\` held 205 rows, of which 4 came from
      -- ledger, none from an operator and none from the system. All 873 were refused; 20 were
      -- still retrying and the rest had been given up on and marked published.
      --
      -- The shape of it is the part worth keeping: this failed ONLY for the two actor kinds whose
      -- actions are hardest to reconstruct from anywhere else — a scheduled job and a human
      -- operator adjusting the ledger by hand, which is the act SD-10 requires two operators and a
      -- reason code for — and it presented as a producer's circuit breaker, which says nothing
      -- about audit to whoever reads it.
      --
      -- ledger is where it BIT, not where it ends. Two more producers emit an audited topic with
      -- the bare 'system' actor and have simply not fired yet on mainnet:
      -- tessera/src/kiln.ts:448 (\`tessera.object.anchored\`) and billing/src/entitlements.ts:441
      -- (\`billing.entitlement.revoked\`, from the entitlement-expiry leased job). Both outboxes are
      -- empty of those topics today. Fixing this only where it was observed would have left two
      -- services that break the estate's audit trail the first time a kiln anchors or an
      -- entitlement lapses.
      --
      -- And the estate already had the right predicate written down, once: tessera's own outbox
      -- CHECK (tessera/src/migrations.ts:1258) is
      --
      --     check (actor = 'system' or actor ~ '^(user|service|operator):.+$')
      --
      -- which is the contract's full vocabulary. This service was the outlier, not the pioneer.
      --
      -- ── WHAT THE NEW PREDICATE IS, AND WHY EACH PIECE OF IT ──
      --
      -- It mirrors \`parseActor\` and nothing else. A second definition of "principal" that is
      -- merely wider is how this recurs in the other direction; the only defensible width is the
      -- contract's exact one.
      --
      --   \`actor = 'system'\`   Bare, no subject. \`parseActor('system')\` returns
      --                        { kind: 'system', id: null } and every producer's envelope builder
      --                        defaults to this string for work no principal asked for. A
      --                        'system:something' form is NOT admitted, because the contract does
      --                        not produce one and a kind with an optional subject is a kind you
      --                        cannot group by.
      --   \`operator:\`          Added. An operator acting as themselves is the case the original
      --                        comment on this column was written about.
      --   \`@\` still absent     from the character class, so \`service:admin-api@replica\` is still
      --                        refused. That is not incidental: src/approvals.ts:409 and
      --                        src/jobs.ts:56 both cite THIS constraint for that refusal, on the
      --                        argument that an actor is an identity and two replicas are one
      --                        identity. Widening the kinds must not widen the subject, and this
      --                        does not.
      --   a bare uuid          still refused — src/audit.test.ts asserts it by constraint name.
      --
      -- The character class stays \`[A-Za-z0-9:._-]{1,128}\`, which IS narrower than \`parseActor\` —
      -- that accepts any non-empty subject, so a subject containing a space would be legal on the
      -- wire and refused here. That divergence is kept ON PURPOSE and is the one place this
      -- constraint may legitimately be stricter than the contract, because widening the class to
      -- \`.+\` is exactly what would readmit \`service:x@replica\`. Narrower in the SUBJECT is a
      -- deliberate bound on a free-text field; narrower in the KIND was the bug, because a kind is
      -- a closed set the contract enumerates and this service does not get a different one.
      --
      -- The column comment in version 5 ("A principal — 'user:<uuid>' or 'service:<name>' — never
      -- a bare id") is superseded by this block and is deliberately left standing: a released
      -- migration is hash-pinned and \`migrations.test.ts\` refuses a set in which one was edited
      -- after it applied, so correcting the prose there would make every existing database refuse
      -- to boot. Read the two together, newest last, which is the order they are in.
      --
      -- Existing rows are unaffected: every one of them already satisfies the narrower predicate,
      -- so the ALTER validates without a rewrite. Nothing is back-filled here. The 853 events that
      -- were refused and then marked published are still in ledger's outbox and are recoverable by
      -- replay, but whether the log of record should gain rows whose \`recorded_at\` is weeks after
      -- their \`occurred_at\` is a decision about what that table means, not a migration.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      alter table audit_events drop constraint if exists audit_events_actor_is_a_principal;
      alter table audit_events add constraint audit_events_actor_is_a_principal
        check (actor = 'system' or actor ~ '^(user|service|operator):[A-Za-z0-9:._-]{1,128}$');
    `,
  },
  {
    version: 12,
    name: 'decider-is-not-the-subject',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- FOUR EYES COUNTED THE SIGNATURES AND NEVER LOOKED AT WHO BENEFITED. micro-org#317.
      --
      -- Version 6 added \`approvals_no_self_approval\` — \`decided_by <> requested_by\` — and
      -- src/approvals.ts enforces the same rule twice more, in the pre-read and in the UPDATE's
      -- WHERE. Three layers, and all three guard the same fact: that two DIFFERENT operators
      -- touched the row. None of them looks at \`subject_id\`.
      --
      -- So this passed every layer: operator A raises \`identity.role.grant\` naming operator B as
      -- the subject, and B approves it. Two humans, two distinct principals, one of whom has just
      -- awarded themselves \`admin\`. 13-operational-model.md §16 is quoted in version 6's own SQL
      -- as the governing rule and it is about the PERSON WHO BENEFITS not being the person who
      -- decides — the requester/decider split is how that is usually spelled, not what it means.
      --
      -- The gap is narrower than "any escalation" and that is precisely why it survived a review:
      -- B cannot act alone, an audit row names both of them, and the request is visible in the
      -- queue the whole time. It is a control that reads as intact from every angle except the one
      -- that matters, which is the angle from which somebody stands to gain.
      --
      -- ── WHAT THE PREDICATE IS, AND WHY IT IS SHAPED THIS WAY ──
      --
      --   \`decided_by is null\`      A pending or expired row has no decider and cannot violate
      --                             this. Same first clause as \`approvals_no_self_approval\`, for
      --                             the same reason: the constraint is about a DECISION, and rows
      --                             that carry none must stay insertable.
      --   \`subject_kind <> 'user'\`  A subject that is a ledger entry, a moderation case, an
      --                             entitlement, an engagement account or a backup run is not a
      --                             principal and can never equal one. Only \`identity.role.grant\`
      --                             and \`identity.role.revoke\` carry \`subject_kind = 'user'\`
      --                             today, and scoping the check to them is what keeps it from
      --                             comparing strings that are not comparable.
      --   \`'user:' || subject_id\`   The two columns are in DIFFERENT vocabularies and that is not
      --                             an accident to be tidied away: \`subject_id\` is the identifier
      --                             the UPSTREAM uses, a bare uuid for identity's route, while
      --                             \`decided_by\` is an estate PRINCIPAL and
      --                             \`approvals_decider_is_a_principal\` pins it to '^user:...'.
      --                             The concatenation is the conversion between them, written
      --                             here rather than assumed, and it is why this cannot be a
      --                             plain column comparison.
      --
      -- The REQUESTER is deliberately NOT covered. Raising a request naming yourself is asking,
      -- and asking is not authority: some other operator still has to sign, and forcing a colleague
      -- to type the request on your behalf would hide who wanted it while changing nothing about
      -- who authorised it. The audit row would then be less true, not more.
      --
      -- MEASURED ON MAINNET BEFORE WRITING THIS, 2026-08-10: \`approvals\` in the estate's
      -- \`admin_api\` database holds 3 rows, all 3 with \`subject_kind = 'user'\`, and 0 of them
      -- with a non-null \`decided_by\` — so no row violates the new predicate, the ALTER validates
      -- without a rewrite, and nothing is back-filled. Worth reading twice: every approval this
      -- estate has ever raised names a USER as its subject, so the case this constraint covers is
      -- not an exotic corner of the catalogue, it is the only case anyone has used. It has simply
      -- never been decided. Had a violating row existed the answer would have been to add the
      -- constraint NOT VALID and investigate the row, not to soften the predicate.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      alter table approvals add constraint approvals_decider_is_not_the_subject
        check (
          decided_by is null
          or subject_kind <> 'user'
          or decided_by <> 'user:' || subject_id
        );
    `,
  },
]

/**
 * The version this build requires. `index.ts` asserts it at boot and refuses to serve below it.
 *
 * More than hygiene here: below version 5 there is no `audit_events_chain_uniq`, so the audit log
 * is a set of rows rather than a chain and two concurrent appenders can fork it silently; below
 * version 6 there is no `approvals_no_self_approval`, so a single operator can approve their own
 * ledger reversal. Both are the controls this service exists to add, and a service that could
 * create them at boot is a service that could start without them.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce((max, m) => Math.max(max, m.version), 0)

/**
 * A new service leaves this at 0.
 *
 * There is nothing to baseline against. 03-repository-responsibilities.md:50 derives this service
 * from `platform/services/nimbus`'s admin proxies, and a proxy has no schema: nimbus's audit is
 * `log.warn({audit: …})` (SD-11), a log line, and there is no approvals table, no flag table and
 * no broadcast table anywhere in the frozen estate. Nothing is ported and nothing is adopted.
 */
export const BASELINE_VERSION = 0

/** Every table this service owns, for the test harness's truncate. Order is child-first. */
export const TABLES: readonly string[] = Object.freeze([
  'restore_runs',
  'backup_artefacts',
  'backup_runs',
  'backup_settings',
  'estate_identity',
  'engagement_transfers',
  'engagement_policies',
  'engagement_fee_recycle',
  'audit_chain_checkpoints',
  'audit_subject_erasures',
  'audit_events',
  'approvals',
  'broadcasts',
  'feature_flags',
  'idempotency_keys',
  'inbox',
  'outbox_deliveries',
  'event_subscriptions',
  'outbox',
])

/** Sequences that must be restarted alongside the truncate, since they are not owned by a column. */
export const SEQUENCES: readonly string[] = Object.freeze(['audit_events_seq'])
