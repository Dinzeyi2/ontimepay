/**
 * services/webhook/index.js
 * Handles ONLY: Stripe Issuing JIT auth, Stripe Treasury updates, AfterShip delivery.
 *
 * This service is LATENCY-CRITICAL. Stripe's synchronous issuing_authorization.request
 * must receive a response within ~2 seconds or it times out and declines.
 *
 * Rules for this file:
 *   ✓ DO: fast DB lookups, synchronous auth decisions, enqueue background work
 *   ✗ DO NOT: inline payout calls, external HTTP, slow joins, heavy logging in auth path
 *
 * Deploy as a SEPARATE Railway service from the API.
 * Scale independently — keep it lean and healthy.
 */
require("dotenv").config();
const express = require("express");
const crypto  = require("crypto");
const Stripe  = require("stripe");

const {
  makeLogger, makePool, makeStripe, Queue,
  ledgerEntry, transitionStatus,
  isEventProcessed, verifyAfterShipSignature,
  cancelTransactionCard, requireEnv,
} = require("../../shared");

requireEnv([
  "DATABASE_URL", "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET", "AFTERSHIP_WEBHOOK_SECRET",
]);

const log    = makeLogger("webhook");
// Webhook service uses a small pool — it's lean by design
const db     = makePool(5);
const stripe = makeStripe();
const queue  = new Queue(db, log);

const app = express();
app.set("trust proxy", 1);

// Raw body BEFORE any other parser — webhooks need the raw buffer for signature verification
app.use("/webhooks/stripe",    express.raw({ type: "application/json" }));
app.use("/webhooks/aftership", express.raw({ type: "application/json" }));

// ─────────────────────────────────────────────────────────────────────────────
// STRIPE ISSUING WEBHOOK
// ─────────────────────────────────────────────────────────────────────────────
app.post("/webhooks/stripe", async (req, res) => {
  let event;
  try {
    event = Stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    log.error("Stripe signature failed", { err: err.message });
    return res.status(400).json({ error: `Signature failed: ${err.message}` });
  }

  // ── SYNCHRONOUS: Real-time JIT authorization ──────────────────────────────
  // Stripe waits for this response. Must be fast. No external calls. No heavy work.
  // card_id IS the transaction — one card was issued for exactly one order.
  if (event.type === "issuing_authorization.request") {
    const auth = event.data.object;
    const startMs = Date.now();
    try {
      const { rows } = await db.query(
        `SELECT t.id, t.amount_cents, t.status, u.is_active
         FROM transactions t JOIN users u ON u.id = t.user_id
         WHERE t.stripe_card_id = $1`,
        [auth.card.id]
      );

      if (!rows.length) {
        log.warn("JIT: card not found", { card_id: auth.card.id, auth_id: auth.id });
        return res.json({ approved: false, reason: "card_not_found" });
      }
      const txn = rows[0];

      const amountOk = Math.abs(auth.pending_request.amount - txn.amount_cents) / txn.amount_cents <= 0.10;
      const eligible = txn.status === "pending"
                    && txn.is_active
                    && auth.card.status === "active"
                    && amountOk;

      log.info("JIT decision", {
        txn_id:    txn.id,
        auth_id:   auth.id,
        approved:  eligible,
        reason:    eligible ? null : (!amountOk ? "amount_mismatch" : "ineligible_state"),
        latency_ms: Date.now() - startMs,
      });

      return res.json({
        approved: eligible,
        ...(eligible ? {} : { reason: !amountOk ? "amount_mismatch" : "ineligible_state" }),
      });
    } catch (err) {
      log.error("JIT auth error", { err: err.message, auth_id: auth.id, latency_ms: Date.now() - startMs });
      // Fail safe: decline on any internal error
      return res.json({ approved: false, reason: "internal_error" });
    }
  }

  // ── ASYNC: All remaining events — enqueue for worker ─────────────────────
  // Don't process inline. Just record and return 200 fast.
  if (await isEventProcessed(db, event.id)) return res.json({ received: true });

  const asyncEvents = [
    "issuing_authorization.created",
    "issuing_transaction.created",
    "treasury.outbound_payment.posted",
    "treasury.outbound_payment.failed",
    "treasury.outbound_payment.returned",
    "treasury.outbound_payment.canceled",
  ];

  if (asyncEvents.includes(event.type)) {
    try {
      await queue.enqueue(
        "process_stripe_event",
        { event_type: event.type, event_data: event.data.object },
        { priority: event.type.startsWith("treasury") ? 2 : 3 }
      );
      log.info("Stripe event enqueued", { event_type: event.type, event_id: event.id });
    } catch (err) {
      log.error("Failed to enqueue stripe event", { event_type: event.type, err: err.message });
      // Return 200 anyway — Stripe will retry if we 5xx, but we've already deduped
    }
  }

  res.json({ received: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// AFTERSHIP WEBHOOK — Delivery Detection
// ─────────────────────────────────────────────────────────────────────────────
app.post("/webhooks/aftership", async (req, res) => {
  try {
    verifyAfterShipSignature(req.body, req.headers["am-webhook-signature"]);
  } catch (err) {
    return res.status(err.status || 400).json({ error: err.message });
  }

  let payload;
  try { payload = JSON.parse(req.body.toString()); }
  catch { return res.status(400).json({ error: "Invalid JSON" }); }

  const tracking = payload?.msg?.tracking;
  if (!tracking) return res.json({ received: true });

  log.info("AfterShip event", { tag: tracking.tag, tracking_number: tracking.tracking_number });

  // Only act on Delivered — enqueue for worker to handle state transition
  if (tracking.tag === "Delivered") {
    await queue.enqueue(
      "mark_delivered",
      { tracking_number: tracking.tracking_number },
      { priority: 1 }
    ).catch(err => log.error("Failed to enqueue mark_delivered", { err: err.message }));
  }

  res.json({ received: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({
  status: "ok", service: "ontimepay-webhook", version: "5.0.0", ts: new Date(),
}));

const PORT = process.env.WEBHOOK_PORT || 3001;
app.listen(PORT, () => log.info("Webhook service started", { port: PORT }));
