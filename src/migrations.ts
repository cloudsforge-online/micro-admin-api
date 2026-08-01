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
  'audit_chain_checkpoints',
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
