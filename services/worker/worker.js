/**
 * services/worker/index.js
 * Processes all background jobs from job_queue:
 *   - execute_payout          Stripe Treasury OutboundPayment
 *   - process_stripe_event    Post-auth DB linking, capture, Treasury status
 *   - mark_delivered          AfterShip delivered → start 24h window
 *   - settle_expired          Undo window expired → settle transaction
 *   - register_tracking       Register order with AfterShip
 *   - orphan_cleanup          Cancel unlinked Stripe cards
 *   - reconcile               Compare DB vs Stripe on key transactions
 *   - reset_velocity_counters Reset 30d fraud counters (daily)
 *
 * Runs as a SINGLE Railway worker service (not autoscaled).
 * Uses SKIP LOCKED so you CAN run multiple instances safely if needed.
 */
require("dotenv").config();
const axios = require("axios");

const {
  makeLogger, makePool, makeStripe, Queue,
  ledgerEntry, transitionStatus,
  cancelTransactionCard, requireEnv,
} = require("../../shared");

requireEnv([
  "DATABASE_URL", "STRIPE_SECRET_KEY",
  "AFTERSHIP_API_KEY",
]);

const log    = makeLogger("worker");
const db     = makePool(10);
const stripe = makeStripe();
const queue  = new Queue(db, log);

const ALL_JOB_TYPES = [
  "execute_payout",
  "process_stripe_event",
  "mark_delivered",
  "settle_expired",
  "register_tracking",
  "orphan_cleanup",
  "reconcile",
  "reset_velocity_counters",
];

// ─────────────────────────────────────────────────────────────────────────────
// JOB HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

const handlers = {};

// ── execute_payout ────────────────────────────────────────────────────────────
// Fires Stripe Treasury OutboundPayment for an undone transaction.
// Handles missing payout method gracefully (flags for manual review).
handlers.execute_payout = async ({ txn_id }) => {
  const { rows } = await db.query(
    `SELECT t.*, u.stripe_customer_id, u.stripe_payout_method_id
     FROM transactions t JOIN users u ON u.id = t.user_id
     WHERE t.id = $1`,
    [txn_id]
  );
  if (!rows.length) throw new Error(`Transaction ${txn_id} not found`);
  const txn = rows[0];

  if (txn.payout_status === "posted" || txn.payout_status === "canceled")
    return log.info("Payout already terminal — skipping", { txn_id });

  if (!process.env.STRIPE_FINANCIAL_ACCOUNT_ID || !txn.stripe_payout_method_id) {
    await db.query(
      `UPDATE transactions SET payout_status = 'manual_review', updated_at = NOW() WHERE id = $1`,
      [txn_id]
    );
    log.warn("Payout skipped — no method or no financial account", { txn_id });
    return;
  }

  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SELECT id FROM transactions WHERE id = $1 FOR UPDATE`, [txn_id]);

    const payout = await stripe.treasury.outboundPayments.create({
      financial_account:          process.env.STRIPE_FINANCIAL_ACCOUNT_ID,
      amount:                     txn.amount_cents,
      currency:                   "usd",
      customer:                   txn.stripe_customer_id,
      destination_payment_method: txn.stripe_payout_method_id,
      statement_descriptor:       "ONTIMEPAY UNDO",
      description:                `Refund txn ${txn_id} attempt ${txn.payout_attempts + 1}`,
    });

    await client.query(
      `UPDATE transactions
       SET stripe_payout_id = $1, payout_status = 'pending',
           payout_attempts = payout_attempts + 1, payout_last_error = NULL, updated_at = NOW()
       WHERE id = $2`,
      [payout.id, txn_id]
    );
    await ledgerEntry(client, txn_id, txn.user_id, "payout_initiated", txn.amount_cents,
      `Treasury OutboundPayment ${payout.id} — attempt ${txn.payout_attempts + 1}`);

    await client.query("COMMIT");
    log.info("Payout initiated", { txn_id, payout_id: payout.id });
  } catch (err) {
    await client.query("ROLLBACK");
    // Record failure and let the job fail() mechanism schedule retry
    await db.query(
      `UPDATE transactions
       SET payout_status = 'failed', payout_attempts = payout_attempts + 1,
           payout_last_error = $1, updated_at = NOW()
       WHERE id = $2`,
      [err.message.slice(0, 500), txn_id]
    );
    throw err; // re-throw so queue.fail() schedules a retry
  } finally { client.release(); }
};

// ── process_stripe_event ──────────────────────────────────────────────────────
// Handles async Stripe events dequeued from the webhook service.
handlers.process_stripe_event = async ({ event_type, event_data: obj }) => {
  const client = await db.connect();
  try {
    await client.query("BEGIN");

    // Authorization confirmed — link to transaction by card_id
    if (event_type === "issuing_authorization.created") {
      await client.query(
        `UPDATE transactions SET stripe_auth_id = $1, status = 'authorized', updated_at = NOW()
         WHERE stripe_card_id = $2 AND status = 'pending'`,
        [obj.id, obj.card.id]
      );
      log.info("Auth linked", { auth_id: obj.id, card_id: obj.card.id });
    }

    // Capture confirmed — move to funded
    if (event_type === "issuing_transaction.created") {
      const { rows } = await client.query(
        `SELECT * FROM transactions WHERE stripe_auth_id = $1 FOR UPDATE`,
        [obj.authorization]
      );
      if (rows.length && rows[0].status === "authorized") {
        await transitionStatus(client, rows[0].id, "authorized", "funded");
        await ledgerEntry(client, rows[0].id, rows[0].user_id, "debit_bank", obj.amount,
          "Stripe capture confirmed");
        log.info("Transaction funded", { txn_id: rows[0].id });
      }
    }

    // Treasury: payout posted (money is in transit)
    if (event_type === "treasury.outbound_payment.posted") {
      const { rows } = await client.query(
        `SELECT id, user_id, amount_cents FROM transactions WHERE stripe_payout_id = $1 FOR UPDATE`,
        [obj.id]
      );
      if (rows.length) {
        await client.query(
          `UPDATE transactions SET payout_status = 'posted', payout_succeeded_at = NOW(), updated_at = NOW()
           WHERE id = $1`,
          [rows[0].id]
        );
        await ledgerEntry(client, rows[0].id, rows[0].user_id, "payout_posted", rows[0].amount_cents,
          `Treasury payout ${obj.id} posted`);
        log.info("Payout posted", { txn_id: rows[0].id, payout_id: obj.id });
      }
    }

    // Treasury: payout failed — set back to 'failed' so retry cron picks it up
    if (event_type === "treasury.outbound_payment.failed") {
      const reason = obj.returned_details?.code || "unknown";
      const { rows } = await client.query(
        `SELECT id, user_id, amount_cents FROM transactions WHERE stripe_payout_id = $1 FOR UPDATE`,
        [obj.id]
      );
      if (rows.length) {
        await client.query(
          `UPDATE transactions
           SET payout_status = 'failed', payout_last_error = $1, updated_at = NOW()
           WHERE id = $2`,
          [reason, rows[0].id]
        );
        await ledgerEntry(client, rows[0].id, rows[0].user_id, "payout_failed", rows[0].amount_cents,
          `Treasury payout ${obj.id} failed: ${reason}`);
        log.warn("Payout failed via webhook", { txn_id: rows[0].id, reason });
      }
    }

    // Treasury: payout returned (rare — bank rejected after posting)
    if (event_type === "treasury.outbound_payment.returned") {
      const { rows } = await client.query(
        `SELECT id, user_id, amount_cents FROM transactions WHERE stripe_payout_id = $1 FOR UPDATE`,
        [obj.id]
      );
      if (rows.length) {
        await client.query(
          `UPDATE transactions SET payout_status = 'returned', updated_at = NOW() WHERE id = $1`,
          [rows[0].id]
        );
        await ledgerEntry(client, rows[0].id, rows[0].user_id, "payout_returned", rows[0].amount_cents,
          `Treasury payout ${obj.id} returned — manual review required`);
        log.warn("Payout returned — flagging for manual review", { txn_id: rows[0].id });
      }
    }

    // Treasury: payout canceled
    if (event_type === "treasury.outbound_payment.canceled") {
      const { rows } = await client.query(
        `SELECT id, user_id, amount_cents FROM transactions WHERE stripe_payout_id = $1 FOR UPDATE`,
        [obj.id]
      );
      if (rows.length) {
        await client.query(
          `UPDATE transactions SET payout_status = 'canceled', updated_at = NOW() WHERE id = $1`,
          [rows[0].id]
        );
        await ledgerEntry(client, rows[0].id, rows[0].user_id, "payout_canceled", rows[0].amount_cents,
          `Treasury payout ${obj.id} canceled`);
      }
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally { client.release(); }
};

// ── mark_delivered ────────────────────────────────────────────────────────────
handlers.mark_delivered = async ({ tracking_number }) => {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      `SELECT * FROM transactions WHERE tracking_number = $1 AND status = 'funded' FOR UPDATE`,
      [tracking_number]
    );
    if (!rows.length) {
      await client.query("ROLLBACK");
      log.info("mark_delivered: no funded txn found", { tracking_number });
      return;
    }
    const txn          = rows[0];
    const deliveredAt  = new Date();
    const undoDeadline = new Date(deliveredAt.getTime() + 24 * 60 * 60 * 1000);

    await transitionStatus(client, txn.id, "funded", "delivered", {
      delivered_at:  deliveredAt.toISOString(),
      undo_deadline: undoDeadline.toISOString(),
    });
    await ledgerEntry(client, txn.id, txn.user_id, "delivered",
      txn.amount_cents, `Delivered — 24h UNDO window open until ${undoDeadline.toISOString()}`);
    await client.query("COMMIT");
    log.info("Transaction marked delivered", { txn_id: txn.id, undo_deadline: undoDeadline });
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally { client.release(); }
};

// ── settle_expired ────────────────────────────────────────────────────────────
// Settles all transactions where undo window has passed.
// Enqueued by the scheduler every minute.
handlers.settle_expired = async () => {
  const { rows } = await db.query(
    `SELECT id, user_id, amount_cents, fee_cents, stripe_card_id FROM transactions
     WHERE status = 'delivered' AND undo_deadline < NOW()
     LIMIT 50` // process in batches to avoid long-running locks
  );

  let settled = 0;
  for (const txn of rows) {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT id FROM transactions WHERE id = $1 FOR UPDATE`, [txn.id]);
      await transitionStatus(client, txn.id, "delivered", "settled");
      await ledgerEntry(client, txn.id, txn.user_id, "settle", txn.amount_cents,
        "Undo window expired — purchase settled");
      await ledgerEntry(client, txn.id, txn.user_id, "fee", txn.fee_cents,
        "OnTimePay $7 convenience fee");
      await client.query("COMMIT");
      await cancelTransactionCard(stripe, txn.stripe_card_id);
      settled++;
    } catch (err) {
      await client.query("ROLLBACK");
      // "Transition rejected" = concurrent undo beat us — not an error
      if (!err.message.startsWith("Transition"))
        log.error("settle_expired error", { txn_id: txn.id, err: err.message });
    } finally { client.release(); }
  }
  if (settled > 0) log.info("Settlements complete", { count: settled });
};

// ── register_tracking ─────────────────────────────────────────────────────────
handlers.register_tracking = async ({ tracking_number, carrier, txn_id }) => {
  await axios.post(
    "https://api.aftership.com/v4/trackings",
    { tracking: { tracking_number, slug: carrier } },
    { headers: { "aftership-api-key": process.env.AFTERSHIP_API_KEY }, timeout: 8000 }
  );
  log.info("Tracking registered", { tracking_number, txn_id });
};

// ── orphan_cleanup ────────────────────────────────────────────────────────────
handlers.orphan_cleanup = async () => {
  const { rows } = await db.query(
    `SELECT * FROM stripe_provisioning_log
     WHERE linked = FALSE AND created_at < NOW() - INTERVAL '15 minutes'
     LIMIT 50`
  );
  for (const row of rows) {
    try {
      if (row.type === "card")
        await stripe.issuing.cards.update(row.stripe_id, { status: "canceled" });
      await db.query(`DELETE FROM stripe_provisioning_log WHERE id = $1`, [row.id]);
      log.info("Orphan cleaned", { type: row.type, stripe_id: row.stripe_id });
    } catch (err) {
      log.warn("Orphan cleanup failed", { stripe_id: row.stripe_id, err: err.message });
    }
  }
};

// ── reconcile ─────────────────────────────────────────────────────────────────
// Compares DB state vs Stripe for transactions that may have drifted.
// Catches: missed webhooks, delayed deliveries, duplicate event issues.
handlers.reconcile = async () => {
  // Reconcile transactions that have been in 'pending' payout for > 1 hour
  // by fetching their OutboundPayment status from Stripe directly.
  const { rows } = await db.query(
    `SELECT id, stripe_payout_id, user_id, amount_cents FROM transactions
     WHERE payout_status = 'pending'
       AND stripe_payout_id IS NOT NULL
       AND updated_at < NOW() - INTERVAL '1 hour'
     LIMIT 20`
  );

  for (const txn of rows) {
    try {
      const op = await stripe.treasury.outboundPayments.retrieve(txn.stripe_payout_id);
      const stripeStatus = op.status; // processing | posted | failed | returned | canceled

      if (stripeStatus === "posted" && txn.payout_status !== "posted") {
        const client = await db.connect();
        try {
          await client.query("BEGIN");
          await client.query(
            `UPDATE transactions SET payout_status = 'posted', payout_succeeded_at = NOW(), updated_at = NOW()
             WHERE id = $1`,
            [txn.id]
          );
          await ledgerEntry(client, txn.id, txn.user_id, "payout_posted_reconciled",
            txn.amount_cents, `Reconciled: Stripe status was ${stripeStatus}`);
          await client.query("COMMIT");
          log.info("Reconciled payout", { txn_id: txn.id, stripe_status: stripeStatus });
        } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
      }

      if (["failed", "returned", "canceled"].includes(stripeStatus) && txn.payout_status === "pending") {
        await db.query(
          `UPDATE transactions SET payout_status = $1, payout_last_error = 'reconciled from Stripe', updated_at = NOW()
           WHERE id = $2`,
          [stripeStatus, txn.id]
        );
        log.warn("Reconciled failed payout", { txn_id: txn.id, stripe_status: stripeStatus });
      }
    } catch (err) {
      log.warn("Reconcile fetch failed", { txn_id: txn.id, err: err.message });
    }
  }
};

// ── reset_velocity_counters ───────────────────────────────────────────────────
// Resets 30d rolling fraud counters. Run daily via scheduler.
handlers.reset_velocity_counters = async () => {
  const { rowCount } = await db.query(
    `UPDATE users SET order_count_30d = 0, undo_count_30d = 0
     WHERE updated_at < NOW() - INTERVAL '30 days'`
  );
  log.info("Velocity counters reset", { rows_reset: rowCount });
};

// ─────────────────────────────────────────────────────────────────────────────
// SCHEDULER — Enqueues periodic jobs into the queue
// Single source of truth. SKIP LOCKED means safe even if multiple worker instances run.
// ─────────────────────────────────────────────────────────────────────────────
const { setInterval } = require("timers");

function startScheduler() {
  // Settle expired undo windows — every 30 seconds
  setInterval(async () => {
    await queue.enqueue("settle_expired", {}, { priority: 1 })
      .catch(err => log.error("Failed to enqueue settle_expired", { err: err.message }));
  }, 30_000);

  // Reconcile payout drift — every 10 minutes
  setInterval(async () => {
    await queue.enqueue("reconcile", {}, { priority: 4 })
      .catch(err => log.error("Failed to enqueue reconcile", { err: err.message }));
  }, 10 * 60_000);

  // Orphan cleanup — every 15 minutes
  setInterval(async () => {
    await queue.enqueue("orphan_cleanup", {}, { priority: 5 })
      .catch(err => log.error("Failed to enqueue orphan_cleanup", { err: err.message }));
  }, 15 * 60_000);

  // Velocity counter reset — once per day
  setInterval(async () => {
    await queue.enqueue("reset_velocity_counters", {}, { priority: 5 })
      .catch(err => log.error("Failed to enqueue reset_velocity_counters", { err: err.message }));
  }, 24 * 60 * 60_000);

  // Cleanup old processed_events — once per day
  setInterval(async () => {
    await db.query(`DELETE FROM processed_events WHERE processed_at < NOW() - INTERVAL '7 days'`)
      .then(r => r.rowCount > 0 && log.info("Pruned processed_events", { count: r.rowCount }))
      .catch(err => log.error("processed_events cleanup failed", { err: err.message }));
  }, 24 * 60 * 60_000);

  // Prune dead/done jobs older than 7 days — daily
  setInterval(async () => {
    await db.query(
      `DELETE FROM job_queue WHERE status IN ('done','dead') AND updated_at < NOW() - INTERVAL '7 days'`
    ).catch(err => log.error("Job pruning failed", { err: err.message }));
  }, 24 * 60 * 60_000);

  log.info("Scheduler started");
}

// ─────────────────────────────────────────────────────────────────────────────
// POLL LOOP — Continuously dequeues and processes jobs
// ─────────────────────────────────────────────────────────────────────────────
async function pollLoop() {
  while (true) {
    let job = null;
    try {
      job = await queue.dequeue(ALL_JOB_TYPES);
      if (!job) {
        await sleep(500); // no work — back off briefly
        continue;
      }

      const handler = handlers[job.type];
      if (!handler) {
        log.warn("No handler for job type", { type: job.type, job_id: job.id });
        await queue.complete(job.id);
        continue;
      }

      log.info("Processing job", { type: job.type, job_id: job.id, attempt: job.attempts });
      await handler(job.payload);
      await queue.complete(job.id);
      log.info("Job complete", { type: job.type, job_id: job.id });

    } catch (err) {
      if (job) {
        const result = await queue.fail(job.id, err, 3);
        log.error("Job failed", {
          type: job?.type, job_id: job?.id, err: err.message,
          new_status: result?.status, attempts: result?.attempts,
        });
        if (result?.status === "dead")
          log.error("Job is dead — manual review required", { type: job.type, job_id: job.id });
      } else {
        log.error("Poll loop error", { err: err.message });
        await sleep(2000);
      }
    }
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH (simple HTTP for Railway's health check)
// ─────────────────────────────────────────────────────────────────────────────
const express = require("express");
const healthApp = express();
healthApp.get("/health", async (_, res) => {
  const { rows } = await db.query(
    `SELECT status, COUNT(*) as count FROM job_queue GROUP BY status`
  ).catch(() => ({ rows: [] }));
  res.json({
    status:  "ok",
    service: "ontimepay-worker",
    version: "5.0.0",
    jobs:    Object.fromEntries(rows.map(r => [r.status, parseInt(r.count)])),
    ts:      new Date(),
  });
});

const HEALTH_PORT = process.env.WORKER_HEALTH_PORT || 3002;
healthApp.listen(HEALTH_PORT);

// ─────────────────────────────────────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────────────────────────────────────
startScheduler();
pollLoop().catch(err => {
  log.error("Poll loop crashed", { err: err.message });
  process.exit(1);
});
log.info("Worker service started", { health_port: HEALTH_PORT });
