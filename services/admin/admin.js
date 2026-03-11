/**
 * services/admin/index.js
 * Internal ops tooling. NOT exposed publicly.
 * Protect behind VPN / IP allowlist in Railway or a reverse proxy.
 *
 * Capabilities:
 *   - View full ledger per transaction
 *   - Manual payout retry / cancel
 *   - User suspension / reinstatement
 *   - Dead job review and replay
 *   - Orphan Stripe object inspection
 *   - Payout metrics / dashboard
 *   - Webhook replay visibility (processed_events)
 */
require("dotenv").config();
const express  = require("express");
const crypto   = require("crypto");
const { makeLogger, makePool, makeStripe, Queue, requireEnv } = require("../../shared");

requireEnv(["DATABASE_URL", "STRIPE_SECRET_KEY", "ADMIN_SECRET"]);

const log    = makeLogger("admin");
const db     = makePool(5);
const stripe = makeStripe();
const queue  = new Queue(db, log);
const app    = express();
app.use(express.json({ limit: "64kb" }));

// ── Admin auth: static secret in Authorization header ─────────────────────────
// Replace with proper RBAC / SSO for a real team.
function requireAdmin(req, res, next) {
  const provided = req.headers["authorization"]?.replace("Bearer ", "");
  const expected = process.env.ADMIN_SECRET;
  if (!provided || provided.length !== expected.length) return res.status(401).end();
  // Timing-safe compare to prevent header enumeration
  try {
    const match = crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
    if (!match) return res.status(401).end();
  } catch { return res.status(401).end(); }
  next();
}
app.use(requireAdmin);

// ─────────────────────────────────────────────────────────────────────────────
// PAYOUT OPS
// ─────────────────────────────────────────────────────────────────────────────

// GET /admin/payouts/pending — transactions needing manual review
app.get("/admin/payouts/pending", async (req, res) => {
  const { rows } = await db.query(`
    SELECT t.id, t.user_id, t.amount_cents, t.payout_status, t.payout_attempts,
           t.payout_last_error, t.stripe_payout_id, t.updated_at,
           u.email
    FROM transactions t
    JOIN users u ON u.id = t.user_id
    WHERE t.payout_status IN ('failed', 'manual_review', 'returned')
    ORDER BY t.payout_attempts DESC, t.updated_at ASC
    LIMIT 100
  `);
  res.json({ count: rows.length, payouts: rows });
});

// POST /admin/payouts/:txn_id/retry — manually queue a payout retry
app.post("/admin/payouts/:txn_id/retry", async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, payout_status FROM transactions WHERE id = $1`, [req.params.txn_id]
  );
  if (!rows.length) return res.status(404).json({ error: "Transaction not found" });
  if (!["failed", "manual_review", "returned"].includes(rows[0].payout_status))
    return res.status(400).json({ error: `Cannot retry payout in status '${rows[0].payout_status}'` });

  // Reset attempts counter to allow retry beyond normal max
  await db.query(
    `UPDATE transactions SET payout_attempts = 0, payout_status = 'failed', updated_at = NOW()
     WHERE id = $1`,
    [req.params.txn_id]
  );
  await queue.enqueue("execute_payout", { txn_id: req.params.txn_id }, { priority: 1 });
  log.info("Admin payout retry queued", { txn_id: req.params.txn_id, admin_ip: req.ip });
  res.json({ success: true, message: "Payout retry queued" });
});

// POST /admin/payouts/:txn_id/mark-resolved — manually mark a payout resolved (e.g. paid offline)
app.post("/admin/payouts/:txn_id/mark-resolved", async (req, res) => {
  const { note = "Manually resolved by admin" } = req.body;
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      `SELECT id, user_id, amount_cents FROM transactions WHERE id = $1 FOR UPDATE`,
      [req.params.txn_id]
    );
    if (!rows.length) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Not found" }); }
    const txn = rows[0];
    await client.query(
      `UPDATE transactions
       SET payout_status = 'posted', payout_succeeded_at = NOW(), updated_at = NOW()
       WHERE id = $1`,
      [txn.id]
    );
    await client.query(
      `INSERT INTO ledger (transaction_id, user_id, type, amount_cents, note, meta)
       VALUES ($1,$2,'admin_resolved',$3,$4,$5)`,
      [txn.id, txn.user_id, txn.amount_cents, note, JSON.stringify({ admin_ip: req.ip })]
    );
    await client.query("COMMIT");
    log.info("Admin marked payout resolved", { txn_id: txn.id, admin_ip: req.ip });
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// LEDGER INSPECTION
// ─────────────────────────────────────────────────────────────────────────────

// GET /admin/transactions/:id/ledger — full ledger for a transaction
app.get("/admin/transactions/:id/ledger", async (req, res) => {
  const { rows: txn } = await db.query(
    `SELECT t.*, u.email FROM transactions t JOIN users u ON u.id = t.user_id WHERE t.id = $1`,
    [req.params.id]
  );
  if (!txn.length) return res.status(404).json({ error: "Transaction not found" });

  const { rows: ledger } = await db.query(
    `SELECT * FROM ledger WHERE transaction_id = $1 ORDER BY created_at ASC`,
    [req.params.id]
  );
  res.json({ transaction: txn[0], ledger });
});

// GET /admin/users/:id/ledger — full ledger history for a user
app.get("/admin/users/:id/ledger", async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 50, 500);
  const offset = parseInt(req.query.offset) || 0;
  const { rows } = await db.query(
    `SELECT l.*, t.status as txn_status FROM ledger l
     LEFT JOIN transactions t ON t.id = l.transaction_id
     WHERE l.user_id = $1 ORDER BY l.created_at DESC LIMIT $2 OFFSET $3`,
    [req.params.id, limit, offset]
  );
  res.json({ count: rows.length, ledger: rows });
});

// ─────────────────────────────────────────────────────────────────────────────
// USER OPS
// ─────────────────────────────────────────────────────────────────────────────

// GET /admin/users/:id
app.get("/admin/users/:id", async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, email, is_active, suspended_at, suspension_reason,
            order_count_30d, undo_count_30d, last_login_at, login_count, created_at
     FROM users WHERE id = $1`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: "User not found" });

  const { rows: txns } = await db.query(
    `SELECT id, amount_cents, status, payout_status, created_at
     FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
    [req.params.id]
  );
  const { rows: signals } = await db.query(
    `SELECT * FROM fraud_signals WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
    [req.params.id]
  );
  res.json({ user: rows[0], recent_transactions: txns, fraud_signals: signals });
});

// POST /admin/users/:id/suspend
app.post("/admin/users/:id/suspend", async (req, res) => {
  const { reason = "Suspended by admin" } = req.body;
  const { rowCount } = await db.query(
    `UPDATE users
     SET is_active = FALSE, suspended_at = NOW(), suspension_reason = $1, updated_at = NOW()
     WHERE id = $2`,
    [reason, req.params.id]
  );
  if (!rowCount) return res.status(404).json({ error: "User not found" });
  // Revoke all sessions
  await db.query(
    `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE user_id = $1`, [req.params.id]
  );
  log.warn("User suspended by admin", { user_id: req.params.id, reason, admin_ip: req.ip });
  res.json({ success: true });
});

// POST /admin/users/:id/reinstate
app.post("/admin/users/:id/reinstate", async (req, res) => {
  const { rowCount } = await db.query(
    `UPDATE users
     SET is_active = TRUE, suspended_at = NULL, suspension_reason = NULL, updated_at = NOW()
     WHERE id = $1`,
    [req.params.id]
  );
  if (!rowCount) return res.status(404).json({ error: "User not found" });
  log.info("User reinstated by admin", { user_id: req.params.id, admin_ip: req.ip });
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// JOB QUEUE OPS
// ─────────────────────────────────────────────────────────────────────────────

// GET /admin/jobs — view dead / stuck jobs
app.get("/admin/jobs", async (req, res) => {
  const status = req.query.status || "dead";
  const { rows } = await db.query(
    `SELECT id, type, payload, status, attempts, last_error, run_at, updated_at
     FROM job_queue WHERE status = $1 ORDER BY updated_at DESC LIMIT 100`,
    [status]
  );
  res.json({ count: rows.length, jobs: rows });
});

// POST /admin/jobs/:id/replay — requeue a dead job
app.post("/admin/jobs/:id/replay", async (req, res) => {
  const { rows } = await db.query(
    `UPDATE job_queue
     SET status = 'pending', attempts = 0, last_error = NULL,
         run_at = NOW(), updated_at = NOW()
     WHERE id = $1 AND status IN ('dead','done')
     RETURNING id, type`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: "Job not found or not replayable" });
  log.info("Admin job replay", { job_id: req.params.id, type: rows[0].type, admin_ip: req.ip });
  res.json({ success: true, job: rows[0] });
});

// DELETE /admin/jobs/dead — purge all dead jobs (irreversible)
app.delete("/admin/jobs/dead", async (req, res) => {
  const { rowCount } = await db.query(`DELETE FROM job_queue WHERE status = 'dead'`);
  log.warn("Admin purged dead jobs", { count: rowCount, admin_ip: req.ip });
  res.json({ success: true, deleted: rowCount });
});

// ─────────────────────────────────────────────────────────────────────────────
// STRIPE ORPHAN INSPECTION
// ─────────────────────────────────────────────────────────────────────────────

app.get("/admin/orphans", async (req, res) => {
  const { rows } = await db.query(
    `SELECT * FROM stripe_provisioning_log
     WHERE linked = FALSE ORDER BY created_at DESC LIMIT 100`
  );
  res.json({ count: rows.length, orphans: rows });
});

app.delete("/admin/orphans/:stripe_id", async (req, res) => {
  const { rows } = await db.query(
    `SELECT * FROM stripe_provisioning_log WHERE stripe_id = $1`, [req.params.stripe_id]
  );
  if (!rows.length) return res.status(404).json({ error: "Not found" });
  if (rows[0].type === "card") {
    await stripe.issuing.cards.update(req.params.stripe_id, { status: "canceled" }).catch(() => {});
  }
  await db.query(`DELETE FROM stripe_provisioning_log WHERE stripe_id = $1`, [req.params.stripe_id]);
  log.info("Admin deleted orphan", { stripe_id: req.params.stripe_id, admin_ip: req.ip });
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// METRICS DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

app.get("/admin/metrics", async (req, res) => {
  const [txnStats, payoutStats, jobStats, userStats] = await Promise.all([
    db.query(`
      SELECT status, COUNT(*) as count, SUM(amount_cents) as total_cents
      FROM transactions GROUP BY status
    `),
    db.query(`
      SELECT payout_status, COUNT(*) as count, SUM(amount_cents) as total_cents
      FROM transactions WHERE status = 'undone' GROUP BY payout_status
    `),
    db.query(`SELECT status, COUNT(*) as count FROM job_queue GROUP BY status`),
    db.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE is_active = TRUE) as active,
        COUNT(*) FILTER (WHERE is_active = FALSE) as suspended,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as new_24h
      FROM users
    `),
  ]);

  res.json({
    transactions: Object.fromEntries(txnStats.rows.map(r => [r.status, {
      count: parseInt(r.count), total_cents: parseInt(r.total_cents || 0)
    }])),
    payouts: Object.fromEntries(payoutStats.rows.map(r => [r.payout_status, {
      count: parseInt(r.count), total_cents: parseInt(r.total_cents || 0)
    }])),
    jobs:  Object.fromEntries(jobStats.rows.map(r => [r.status, parseInt(r.count)])),
    users: userStats.rows[0],
    ts:    new Date(),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FRAUD SIGNALS
// ─────────────────────────────────────────────────────────────────────────────

// GET /admin/fraud — recent fraud signals
app.get("/admin/fraud", async (req, res) => {
  const { rows } = await db.query(`
    SELECT fs.*, u.email FROM fraud_signals fs
    JOIN users u ON u.id = fs.user_id
    ORDER BY fs.created_at DESC LIMIT 100
  `);
  res.json({ count: rows.length, signals: rows });
});

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({
  status: "ok", service: "ontimepay-admin", version: "5.0.0", ts: new Date(),
}));

app.use((err, req, res, _next) => {
  log.error("Admin error", { err: err.message });
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.ADMIN_PORT || 3003;
app.listen(PORT, () => log.info("Admin service started", { port: PORT }));
