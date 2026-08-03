/**
 * Outbox, relay and inbox.
 *
 * Rule 5 of docs/ecosystem/03 §2: every state change others care about writes an outbox row **in
 * the same transaction as the change**. A publish after commit is skipped when the process dies in
 * between; a publish before commit announces something that never happened. Both are silent and
 * both are unrecoverable after the fact.
 *
 * No broker. Postgres already has transactions and `SKIP LOCKED`, and AD-10 records the four
 * measured conditions under which that stops being true.
 *
 * ## The inbox here is the audit mirror, and that changes what it is for
 *
 * 17 §2 requires every service to write "audit events for every privileged action … mirrored to
 * `admin-api`", and 13 §187 names this service's copy as the estate's "tamper-evident mirror".
 * So `POST /v1/events` is not a side channel on this service — it is the intake for the estate's
 * audit of record, and two properties follow that do not follow elsewhere:
 *
 *   1. **The signature is verified over the exact bytes, before `JSON.parse`.** An unsigned audit
 *      intake is a forgery endpoint: anyone who could reach the port could write a row naming any
 *      operator for any action, into the one record a dispute is settled against.
 *
 *   2. **Dedupe is doubled.** `(topic, event_id)` in `inbox` stops the handler running twice;
 *      `audit_events_source_event_uniq` stops a row landing twice even if a future handler forgets
 *      the inbox. At-least-once delivery guarantees redelivery will happen, and an audit log that
 *      shows one privileged action twice is wrong in the direction that gets an innocent operator
 *      suspended.
 */

import { EVENT_ID_HEADER, SIGNATURE_HEADER, signDelivery } from '@cloudsforge/contracts-events'
import type { Sql, TransactionSql } from 'postgres'
import { HttpClient } from '@cloudsforge/http'
import type { Logger } from '@cloudsforge/telemetry'
import type { Handler } from '@cloudsforge/jobs'

export type Db = Sql
export type Tx = TransactionSql

/** What a caller emits. The envelope's `id`, `occurredAt` and `producer` are added here. */
export interface DomainEvent {
  /** `<service>.<aggregate>.<past-tense-verb>` — `admin.flag.changed`. */
  readonly topic: string
  /** Ordering is per `(topic, key)` only. Choose the aggregate id, never a timestamp. */
  readonly key: string
  readonly payload: Record<string, unknown>
  readonly actor?: string
  readonly correlationId?: string
  readonly version?: number
}

/** The wire envelope. Additive-only, versioned per topic, schema-diff enforced — AD-02. */
export interface EventEnvelope {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurredAt: string
  readonly producer: string
  readonly version: number
  readonly actor: string | null
  readonly correlationId: string | null
  readonly payload: Record<string, unknown>
}

/** Write one outbox row on a transaction the caller already holds. */
export async function emitOn(tx: Tx, producer: string, event: DomainEvent): Promise<void> {
  await tx`
    insert into outbox (topic, key, producer, version, actor, correlation_id, payload)
    values (
      ${event.topic},
      ${event.key},
      ${producer},
      ${event.version ?? 1},
      ${event.actor ?? null},
      ${event.correlationId ?? null},
      ${tx.json(event.payload as Record<string, never>)}
    )
  `
}

/* ------------------------------------------------------------------------ signing */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE SIGNING SCHEME IS THE ESTATE'S, NOT THIS SERVICE'S OWN.**
 *
 * This module used to hand-roll one: header `x-cloudsforge-signature`, value
 * `sha256=<hmac(body)>`. Every other service in the estate speaks `contracts-events`' scheme —
 * header `cf-signature`, value `t=<seconds>,v1=<hmac("<seconds>.<body>")>`. The two agree on
 * neither the header NAME nor the value FORMAT, and that had two consequences, both measured
 * against the running estate rather than read off a diff:
 *
 *   1. **Inbound, the audit mirror was unreachable.** A correctly signed delivery from a real
 *      producer arrived with `cf-signature`, this service looked for `x-cloudsforge-signature`,
 *      found nothing, and answered `401 bad_signature` — before the bearer check that was the
 *      other half of the same defect. So the estate's tamper-evident audit of record received
 *      nothing at all, which is what `docs/ecosystem/17` §7 claim 9 rests on.
 *
 *   2. **Outbound, this service's own events were unreadable.** The relay below signed with the
 *      hand-rolled scheme, so `micro-notify`, `micro-analytics` and `micro-activity` — all of
 *      which verify with `verifyDelivery` — would refuse every event this service publishes.
 *
 * Adopting the estate scheme is also strictly STRONGER, which is why this is the direction of the
 * fix rather than teaching the producers to speak the local dialect:
 *
 *   - **It has a timestamp, inside the signed message.** The old scheme had none, so a captured
 *     request stayed valid for ever. On an audit intake — the one record a dispute is settled
 *     against — an unbounded replay window means a captured "operator X reversed entry Y" can be
 *     re-posted at will. `DELIVERY_TOLERANCE_MS` closes it to five minutes.
 *   - **It takes a LIST of secrets**, so a rotation is a window rather than a flag day.
 *   - **It is one implementation, verified by its owner's tests**, rather than a fourth copy of a
 *     MAC comparison in a repository that does not own the wire format.
 *
 * Nothing about "verify before parsing" changes; that property was already right here and is what
 * the file header argues for. What changes is that the verification now matches what is sent.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export { SIGNATURE_HEADER, EVENT_ID_HEADER }

/* ------------------------------------------------------------------------ relay */

export interface RelayDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly signingSecret: string
  readonly batchSize?: number
  readonly deadlineMs?: number
  /** Test seam. Production builds one `HttpClient` per subscription URL. */
  readonly clientFor?: (url: string) => Pick<HttpClient, 'request'>
}

interface OutboxRow {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurred_at: Date
  readonly producer: string
  readonly version: number
  readonly actor: string | null
  readonly correlation_id: string | null
  readonly payload: Record<string, unknown>
}

interface SubscriptionRow {
  readonly id: string
  readonly url: string
}

/**
 * The relay job.
 *
 * A leased job rather than a `setInterval`, for the reason rule 8 exists: two replicas running an
 * interval-driven relay both read the same unpublished rows and every subscriber receives every
 * event twice. The lease key names the contended resource — the outbox stream — so exactly one
 * replica relays at a time whatever the replica count is.
 */
export function createRelay(deps: RelayDeps): Handler {
  const batchSize = deps.batchSize ?? 50
  const deadlineMs = deps.deadlineMs ?? 5_000
  // Clients are cached for the life of the process so a circuit breaker accumulates state across
  // ticks. A fresh client per tick has a permanently closed circuit and hammers a dead subscriber.
  const clients = new Map<string, Pick<HttpClient, 'request'>>()
  const clientFor =
    deps.clientFor ??
    ((url: string) => {
      const existing = clients.get(url)
      if (existing) return existing
      const parsed = new URL(url)
      const client = new HttpClient({ baseUrl: parsed.origin, name: `subscriber:${parsed.host}` })
      clients.set(url, client)
      return client
    })

  return async (_job, ctx) => {
    const events = await deps.sql<OutboxRow[]>`
      select id, topic, key, occurred_at, producer, version, actor, correlation_id, payload
        from outbox
       where published_at is null
       order by occurred_at
       limit ${batchSize}
    `

    for (const event of events) {
      if (ctx.signal.aborted) return

      const subscriptions = await deps.sql<SubscriptionRow[]>`
        select id, url from event_subscriptions where topic = ${event.topic} and active = true
      `

      const envelope: EventEnvelope = {
        id: event.id,
        topic: event.topic,
        key: event.key,
        occurredAt: event.occurred_at.toISOString(),
        producer: event.producer,
        version: event.version,
        actor: event.actor,
        correlationId: event.correlation_id,
        payload: event.payload,
      }
      // The signed bytes and the sent bytes must be identical or every subscriber 401s.
      //
      // Stated honestly rather than assumed: `HttpClient.request` takes an object and calls
      // `JSON.stringify` on it ITSELF (`runtime/packages/http/src/index.ts:352`), so it cannot be
      // handed the pre-serialised string — that would double-encode. What makes this safe is that
      // both sides call the same `JSON.stringify` on the same object, which is deterministic. It
      // is a coupling, not a proof, so `outbox.test.ts` closes it from the other end: it takes the
      // body the client actually received and checks `verifyDelivery` accepts it under this
      // signature. If the client ever serialises differently, that test goes red rather than
      // twenty-one subscribers going quiet.
      const signature = signDelivery(JSON.stringify(envelope), deps.signingSecret)

      for (const subscription of subscriptions) {
        await deliver(deps, clientFor, subscription, envelope, signature, deadlineMs)
      }

      // ══════════════════════════════════════════════════════════════════════════════════════
      // Published only when NOTHING IS OUTSTANDING, so an undelivered subscriber keeps the event
      // in the unpublished set and the next pass retries it.
      //
      // **AND THE LIMIT OF THAT, STATED PRECISELY.** The delivery rows are computed from the LIVE
      // subscription set on every pass, so a subscriber added while an event is still outstanding
      // DOES receive it. A subscriber added after the event already published does NOT — with zero
      // active subscriptions the outstanding count is zero, the event publishes on the first pass,
      // and it is never reconsidered.
      //
      // That is the right behaviour (a subscription is not a replay request) but it is NOT what
      // the comment inherited from `service-template/src/outbox.ts:205` claims, which says flatly
      // that "a subscriber added after the event was written still receives it" — and which is
      // carried verbatim by eighteen repositories, `market/src/outbox.ts:239-241` among them.
      // Both directions are pinned in `outbox.test.ts` so this repository's comment matches this
      // repository's code. Reported rather than fixed in the siblings: this repository does not
      // edit them, and the correction belongs in the template first or it keeps propagating.
      // ══════════════════════════════════════════════════════════════════════════════════════
      const outstanding = await deps.sql<{ n: number }[]>`
        select count(*)::int as n
          from event_subscriptions s
          left join outbox_deliveries d
            on d.subscription_id = s.id and d.event_id = ${event.id}
         where s.topic = ${event.topic}
           and s.active = true
           and d.delivered_at is null
      `
      if ((outstanding[0]?.n ?? 0) === 0) {
        await deps.sql`update outbox set published_at = now() where id = ${event.id}`
      }

      // A long backlog must not outlive the lease and hand the same events to a second replica.
      await ctx.heartbeat()
    }
  }
}

async function deliver(
  deps: RelayDeps,
  clientFor: (url: string) => Pick<HttpClient, 'request'>,
  subscription: SubscriptionRow,
  envelope: EventEnvelope,
  signature: string,
  deadlineMs: number,
): Promise<boolean> {
  const claimed = await deps.sql<{ delivered_at: Date | null }[]>`
    insert into outbox_deliveries (event_id, subscription_id, attempts)
    values (${envelope.id}, ${subscription.id}, 0)
    on conflict (event_id, subscription_id) do update set attempts = outbox_deliveries.attempts + 1
    returning delivered_at
  `
  if (claimed[0]?.delivered_at) return true

  const parsed = new URL(subscription.url)
  try {
    await clientFor(subscription.url).request(`${parsed.pathname}${parsed.search}`, {
      method: 'POST',
      body: envelope,
      deadlineMs,
      idempotencyKey: envelope.id,
      // `EVENT_ID_HEADER`, not the `x-event-id` this file used to hard-code: the estate's constant
      // is `cf-event-id`, and a subscriber reading the contract's spelling saw no id at all.
      headers: { [SIGNATURE_HEADER]: signature, [EVENT_ID_HEADER]: envelope.id },
      ...(envelope.correlationId ? { requestId: envelope.correlationId } : {}),
    })
    await deps.sql`
      update outbox_deliveries set delivered_at = now(), last_error = null
       where event_id = ${envelope.id} and subscription_id = ${subscription.id}
    `
    return true
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    await deps.sql`
      update outbox_deliveries set last_error = ${message.slice(0, 2_000)}
       where event_id = ${envelope.id} and subscription_id = ${subscription.id}
    `
    // Logged, not thrown: one unreachable subscriber must not stop the other subscribers or the
    // rest of the batch. The job succeeds; the undelivered row is the durable record.
    deps.logger.warn('event delivery failed', {
      topic: envelope.topic,
      eventId: envelope.id,
      subscriptionId: subscription.id,
      err: message,
    })
    return false
  }
}

/* ------------------------------------------------------------------------ inbox */

export type InboxOutcome<T> =
  | { readonly status: 'processed'; readonly value: T }
  | { readonly status: 'duplicate' }

/**
 * Run an inbound event's handler exactly once.
 *
 * The insert and the handler share one transaction, so a handler that fails leaves no inbox row
 * and the redelivery is processed rather than swallowed — which is the mistake that makes a naive
 * "record then handle" dedupe lose events.
 */
export async function withInbox<T>(
  sql: Db,
  topic: string,
  eventId: string,
  handle: (tx: Tx) => Promise<T>,
): Promise<InboxOutcome<T>> {
  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ event_id: string }[]>`
      insert into inbox (topic, event_id) values (${topic}, ${eventId})
      on conflict (topic, event_id) do nothing
      returning event_id
    `
    if (claimed.length === 0) return { result: { status: 'duplicate' } as InboxOutcome<T> }
    const value = await handle(tx)
    return { result: { status: 'processed', value } as InboxOutcome<T> }
  })
  return outcome.result
}
