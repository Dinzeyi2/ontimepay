
/**
 * shared/index.js
 * Shared infrastructure used by all 3 services (api, webhook, worker).
 * Import only what each service needs — no circular deps.
 */
require("dotenv").config();
const { Pool }  = require("pg");
const Stripe    = require("stripe");
const crypto    = require("crypto");

// ─────────────────────────────────────────────
// STRUCTURED LOGGER
// Every log line is JSON with a request_id so distributed traces are queryable.
// ─────────────────────────────────────────────
function makeLogger(service) {
  const log = (level, msg, meta = {}) => {
    process.stdout.write(JSON.stringify({
      ts: new Date().toISOString(), level, service, msg, ...meta,
    }) + "\n");
  };
  return {
    info:  (msg, meta) => log("info",  msg, meta),
    warn:  (msg, meta) => log("warn",  msg, meta),
    error: (msg, meta) => log("error", msg, meta),
  };
}

// ─────────────────────────────────────────────
// POSTGRES POOL
// Each service calls makePool() with its own concurrency setting.
// webhook service: max 5 (lean, latency-sensitive)
// api service:     max 15
// worker service:  max 10
// ─────────────────────────────────────────────
function makePool(maxConnections = 10) {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl:              { rejectUnauthorized: false },
    max:              maxConnections,
    idleTimeoutMillis:     30_000,
    connectionTimeoutMillis: 5_000,
    statement_timeout:     10_000, // kill runaway queries after 10s
  });
  pool.on("error", err => console.error(JSON.stringify({ level: "error", msg: "PG pool error", err: err.message })));
  return pool;
}

// ─────────────────────────────────────────────
// STRIPE CLIENT
// ─────────────────────────────────────────────
function makeStripe() {
  return Stripe(process.env.STRIPE_SECRET_KEY, {
    apiVersion: "2023-10-16",
    maxNetworkRetries: 2,
  });
}

// ─────────────────────────────────────────────
// LIGHTWEIGHT QUEUE (Postgres-backed)
// No Redis required for MVP. Uses SKIP LOCKED for safe concurrent dequeue.
// For higher throughput, swap to BullMQ backed by Redis.
// ─────────────────────────────────────────────
class Queue {
  constructor(pool, logger) {
    this.pool   = pool;
    this.logger = logger;
  }

  // enqueue() can be called with OR without a transaction client.
  // With client (transactional): enqueue(client, type, payload, opts)
  // Without client (non-transactional): enqueue(null, type, payload, opts)
  //   — or just enqueue(type, payload, opts) when not inside a transaction
  async enqueue(clientOrType, jobTypeOrPayload, payloadOrOpts, optsOrUndefined) {
    let queryFn, jobType, payload, opts;
    // Detect calling convention
    if (typeof clientOrType === "string") {
      // 3-arg form: enqueue(type, payload, opts?)
      queryFn   = this.pool.query.bind(this.pool);
      jobType   = clientOrType;
      payload   = jobTypeOrPayload;
      opts      = payloadOrOpts || {};
    } else {
      // 4-arg form: enqueue(client, type, payload, opts?)
      queryFn   = clientOrType ? clientOrType.query.bind(clientOrType) : this.pool.query.bind(this.pool);
      jobType   = jobTypeOrPayload;
      payload   = payloadOrOpts;
      opts      = optsOrUndefined || {};
    }
    const { delaySecs = 0, priority = 5 } = opts;
    const runAt = new Date(Date.now() + delaySecs * 1000);
    await queryFn(
      `INSERT INTO job_queue (type, payload, run_at, priority) VALUES ($1, $2, $3, $4)`,
      [jobType, JSON.stringify(payload), runAt, priority]
    );
  }

  // Returns the next available job, skipping locked rows (safe for parallel workers)
  async dequeue(jobTypes) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        `SELECT * FROM job_queue
         WHERE type = ANY($1) AND run_at <= NOW() AND status = 'pending'
         ORDER BY priority ASC, run_at ASC
         LIMIT 1 FOR UPDATE SKIP LOCKED`,
        [jobTypes]
      );
      if (!rows.length) { await client.query("ROLLBACK"); client.release(); return null; }

      const job = rows[0];
      await client.query(
        `UPDATE job_queue SET status = 'processing', attempts = attempts + 1, updated_at = NOW()
         WHERE id = $1`,
        [job.id]
      );
      await client.query("COMMIT");
      client.release();
      return { ...job, payload: JSON.parse(job.payload) };
    } catch (err) {
      await client.query("ROLLBACK");
      client.release();
      throw err;
    }
  }

  async complete(jobId) {
    await this.pool.query(
      `UPDATE job_queue SET status = 'done', updated_at = NOW() WHERE id = $1`, [jobId]
    );
  }

  async fail(jobId, error, maxAttempts = 3) {
    const { rows } = await this.pool.query(
      `UPDATE job_queue
       SET status = CASE WHEN attempts >= $2 THEN 'dead' ELSE 'pending' END,
           last_error = $3,
           run_at = NOW() + (attempts * INTERVAL '10 minutes'),
           updated_at = NOW()
       WHERE id = $1
       RETURNING status, attempts`,
      [jobId, maxAttempts, error.message?.slice(0, 500)]
    );
    return rows[0];
  }
}

// ─────────────────────────────────────────────
// SHARED DB HELPERS
// ─────────────────────────────────────────────

// Append-only ledger — always pass a transaction client
async function ledgerEntry(client, txnId, userId, type, amountCents, note, meta = {}) {
  await client.query(
    `INSERT INTO ledger (transaction_id, user_id, type, amount_cents, note, meta)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [txnId, userId, type, amountCents, note, JSON.stringify(meta)]
  );
}

// Atomic state-machine transition. Throws if current state != expectedFrom.
async function transitionStatus(client, txnId, from, to, extra = {}) {
  const keys    = Object.keys(extra);
  const vals    = Object.values(extra);
  const setCols = keys.map((k, i) => `${k} = $${i + 4}`).join(", ");
  const { rowCount } = await client.query(
    `UPDATE transactions SET status = $3, updated_at = NOW() ${setCols ? ", " + setCols : ""}
     WHERE id = $1 AND status = $2`,
    [txnId, from, to, ...vals]
  );
  if (rowCount === 0)
    throw new Error(`Transition ${from}→${to} rejected for txn ${txnId} (wrong state or not found)`);
}

// Idempotency guard for webhook event IDs
async function isEventProcessed(pool, eventId) {
  try {
    await pool.query(`INSERT INTO processed_events (event_id) VALUES ($1)`, [eventId]);
    return false;
  } catch { return true; }
}

// Verify AfterShip HMAC. Header: "am-webhook-signature", Value: "hmac-sha256=<base64>"
function verifyAfterShipSignature(rawBody, sigHeader) {
  if (!process.env.AFTERSHIP_WEBHOOK_SECRET) return;
  if (!sigHeader) throw Object.assign(new Error("Missing am-webhook-signature"), { status: 401 });
  const eqIdx    = sigHeader.indexOf("=");
  const scheme   = sigHeader.slice(0, eqIdx);
  const received = sigHeader.slice(eqIdx + 1);
  if (scheme !== "hmac-sha256" || !received)
    throw Object.assign(new Error("Malformed signature header"), { status: 401 });
  const expected = crypto.createHmac("sha256", process.env.AFTERSHIP_WEBHOOK_SECRET)
    .update(rawBody).digest("base64");
  const exp = Buffer.from(expected, "base64");
  const rec = Buffer.from(received, "base64");
  if (exp.length !== rec.length || !crypto.timingSafeEqual(exp, rec))
    throw Object.assign(new Error("Invalid signature"), { status: 401 });
}

// Cancel a per-transaction Stripe card
async function cancelTransactionCard(stripe, cardId) {
  try {
    await stripe.issuing.cards.update(cardId, { status: "canceled" });
  } catch (err) {
    console.error(JSON.stringify({ level: "warn", msg: "Card cancel failed", card_id: cardId, err: err.message }));
  }
}

// Boot guard — exits if any required env var is missing
function requireEnv(vars) {
  const missing = vars.filter(k => !process.env[k]);
  if (missing.length) {
    console.error(JSON.stringify({ level: "fatal", msg: "Missing env vars", vars: missing }));
    process.exit(1);
  }
}

module.exports = {
  makeLogger, makePool, makeStripe, Queue,
  ledgerEntry, transitionStatus, isEventProcessed,
  verifyAfterShipSignature, cancelTransactionCard, requireEnv,
};
