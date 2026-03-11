/**
 * services/api/index.js
 * Handles: auth, user management, transaction creation, undo requests.
 * Does NOT handle webhooks (separate service) or background jobs (worker service).
 * Designed to run as multiple stateless Railway instances behind a load balancer.
 */
require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const jwt       = require("jsonwebtoken");
const bcrypt    = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const helmet    = require("helmet");
const axios     = require("axios");

const {
  makeLogger, makePool, makeStripe, Queue,
  ledgerEntry, transitionStatus, requireEnv,
} = require("../../shared");

// ── Boot guards ───────────────────────────────────────────────────────────────
requireEnv([
  "DATABASE_URL", "STRIPE_SECRET_KEY",
  "AFTERSHIP_API_KEY",
  "JWT_SECRET", "JWT_REFRESH_SECRET",
]);

const log    = makeLogger("api");
const db     = makePool(15);
const stripe = makeStripe();
const queue  = new Queue(db, log);

// ── DUMMY_HASH: validated at startup ─────────────────────────────────────────
// Cost-12 bcrypt hash of "__ontimepay_dummy_login_password__"
// Ensures timing-safe login even when email is not found.
const DUMMY_HASH = "$2b$12$PQYFJLZHHSGKgD.nq0/tyu6DWt0n62r7Zezs5sG.EI5M7PBAmDCxW";
(async () => {
  const ok = await bcrypt.compare("__ontimepay_dummy_login_password__", DUMMY_HASH).catch(() => false);
  if (!ok) { log.error("DUMMY_HASH invalid — login timing-safety broken"); process.exit(1); }
  log.info("DUMMY_HASH validated");
})();

// ── App setup ─────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: "64kb" }));
app.use(helmet());
app.set("trust proxy", 1);

// Request ID middleware — attached to every log line for distributed tracing
app.use((req, _res, next) => {
  req.requestId = req.headers["x-request-id"] || crypto.randomUUID();
  req.log = {
    info:  (msg, meta = {}) => log.info(msg,  { request_id: req.requestId, ...meta }),
    warn:  (msg, meta = {}) => log.warn(msg,  { request_id: req.requestId, ...meta }),
    error: (msg, meta = {}) => log.error(msg, { request_id: req.requestId, ...meta }),
  };
  next();
});

// Rate limits
app.use(rateLimit({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 60_000, max: 10 });
const undoLimiter = rateLimit({ windowMs: 60_000, max: 5 });

// ── JWT helpers ───────────────────────────────────────────────────────────────
const signAccess  = (userId, email) =>
  jwt.sign({ sub: userId, email }, process.env.JWT_SECRET, { expiresIn: "15m" });
const signRefresh = (userId, family) =>
  jwt.sign({ sub: userId, fam: family }, process.env.JWT_REFRESH_SECRET, { expiresIn: "30d" });

function requireAuth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ error: "Bearer token required" });
  try {
    const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch (err) {
    res.status(401).json({ error: err.name === "TokenExpiredError" ? "Token expired" : "Invalid token" });
  }
}

async function requireOwnership(req, res, next) {
  if (!req.params.id) return next();
  try {
    const { rows } = await db.query(`SELECT user_id FROM transactions WHERE id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    if (rows[0].user_id !== req.userId) return res.status(403).json({ error: "Forbidden" });
    next();
  } catch (err) { next(err); }
}

// ── Fraud velocity check ─────────────────────────────────────────────────────
async function checkFraudVelocity(userId) {
  const { rows } = await db.query(
    `SELECT order_count_30d, undo_count_30d, is_active FROM users WHERE id = $1`, [userId]
  );
  if (!rows.length) return { allowed: false, reason: "user_not_found" };
  const u = rows[0];
  if (!u.is_active) return { allowed: false, reason: "account_suspended" };
  if (u.order_count_30d >= 20) return { allowed: false, reason: "order_velocity_exceeded" };
  if (u.undo_count_30d >= 5)   return { allowed: false, reason: "undo_velocity_exceeded" };
  return { allowed: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.post("/auth/register", authLimiter, async (req, res) => {
  const { email, password, billing_address } = req.body;
  const addrFields = ["line1", "city", "state", "postal_code", "country"];
  if (!email || !password || !billing_address || addrFields.some(k => !billing_address[k]))
    return res.status(400).json({ error: `Required: email, password, billing_address {${addrFields.join(", ")}}` });
  if (password.length < 10)
    return res.status(400).json({ error: "Password must be at least 10 characters" });

  const client = await db.connect();
  try {
    await client.query("BEGIN");

    const existing = await client.query(`SELECT id FROM users WHERE email = $1`, [email.toLowerCase()]);
    if (existing.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    // Provision Stripe objects — log each before DB insert for orphan recovery
    const customer = await stripe.customers.create({ email: email.toLowerCase() });
    await client.query(
      `INSERT INTO stripe_provisioning_log (type, stripe_id, user_email) VALUES ('customer',$1,$2)`,
      [customer.id, email.toLowerCase()]
    );

    const cardholder = await stripe.issuing.cardholders.create({
      name:    email.split("@")[0],
      email:   email.toLowerCase(),
      type:    "individual",
      billing: { address: billing_address },
      status:  "active",
    });
    await client.query(
      `INSERT INTO stripe_provisioning_log (type, stripe_id, user_email) VALUES ('cardholder',$1,$2)`,
      [cardholder.id, email.toLowerCase()]
    );

    const { rows } = await client.query(
      `INSERT INTO users (email, password_hash, stripe_customer_id, stripe_cardholder_id, billing_address)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, email, created_at`,
      [email.toLowerCase(), passwordHash, customer.id, cardholder.id, JSON.stringify(billing_address)]
    );
    const user = rows[0];

    await client.query(
      `UPDATE stripe_provisioning_log SET linked = TRUE WHERE stripe_id = ANY($1)`,
      [[customer.id, cardholder.id]]
    );

    // Issue tokens
    const family        = crypto.randomUUID();
    const accessToken   = signAccess(user.id, user.email);
    const refreshToken  = signRefresh(user.id, family);
    const refreshHash   = crypto.createHash("sha256").update(refreshToken).digest("hex");

    await client.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at, ip_address, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [user.id, refreshHash, family,
       new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
       req.ip, req.headers["user-agent"]?.slice(0, 200)]
    );
    await client.query(`UPDATE users SET refresh_family = $1 WHERE id = $2`, [family, user.id]);
    await client.query("COMMIT");

    req.log.info("User registered", { user_id: user.id });
    res.status(201).json({ user, access_token: accessToken, refresh_token: refreshToken });
  } catch (err) {
    await client.query("ROLLBACK");
    req.log.error("Registration failed", { err: err.message });
    res.status(500).json({ error: "Registration failed" });
  } finally { client.release(); }
});

// Timing-safe login — always runs bcrypt even for unknown emails
app.post("/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password required" });

  const { rows } = await db.query(
    `SELECT * FROM users WHERE email = $1 AND is_active = TRUE`, [email.toLowerCase()]
  );
  const user  = rows[0] || null;
  const valid = await bcrypt.compare(password, user?.password_hash ?? DUMMY_HASH);
  if (!user || !valid) return res.status(401).json({ error: "Invalid credentials" });

  const family       = crypto.randomUUID();
  const accessToken  = signAccess(user.id, user.email);
  const refreshToken = signRefresh(user.id, family);
  const refreshHash  = crypto.createHash("sha256").update(refreshToken).digest("hex");

  await db.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at, ip_address, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [user.id, refreshHash, family,
     new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
     req.ip, req.headers["user-agent"]?.slice(0, 200)]
  );
  await db.query(
    `UPDATE users SET refresh_family = $1, last_login_at = NOW(), login_count = login_count + 1
     WHERE id = $2`,
    [family, user.id]
  );

  req.log.info("User logged in", { user_id: user.id });
  res.json({ access_token: accessToken, refresh_token: refreshToken,
             user: { id: user.id, email: user.email } });
});

// Refresh with family-based reuse detection
app.post("/auth/refresh", authLimiter, async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: "refresh_token required" });

  let payload;
  try { payload = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET); }
  catch { return res.status(401).json({ error: "Invalid or expired refresh token" }); }

  const hash = crypto.createHash("sha256").update(refresh_token).digest("hex");
  const { rows } = await db.query(
    `SELECT * FROM refresh_tokens WHERE token_hash = $1`, [hash]
  );
  if (!rows.length) return res.status(401).json({ error: "Token not found" });
  const storedToken = rows[0];

  // Reuse detection: if already revoked, the family is compromised — revoke all sessions
  if (storedToken.revoked) {
    req.log.warn("Refresh token reuse detected — revoking entire family", {
      user_id: storedToken.user_id, family: storedToken.family,
    });
    await db.query(
      `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE family = $1`,
      [storedToken.family]
    );
    return res.status(401).json({ error: "Token reuse detected — all sessions revoked" });
  }

  if (storedToken.expires_at < new Date())
    return res.status(401).json({ error: "Refresh token expired" });

  // Rotate token within same family
  await db.query(
    `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE token_hash = $1`, [hash]
  );

  const { rows: u } = await db.query(`SELECT id, email FROM users WHERE id = $1`, [payload.sub]);
  if (!u.length) return res.status(401).json({ error: "User not found" });

  const newAccess  = signAccess(u[0].id, u[0].email);
  const newRefresh = signRefresh(u[0].id, storedToken.family); // same family
  const newHash    = crypto.createHash("sha256").update(newRefresh).digest("hex");

  await db.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at, ip_address, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [u[0].id, newHash, storedToken.family,
     new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
     req.ip, req.headers["user-agent"]?.slice(0, 200)]
  );

  res.json({ access_token: newAccess, refresh_token: newRefresh });
});

app.post("/auth/logout", requireAuth, async (req, res) => {
  const { refresh_token } = req.body;
  if (refresh_token) {
    const hash = crypto.createHash("sha256").update(refresh_token).digest("hex");
    await db.query(
      `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE token_hash = $1`, [hash]
    );
  }
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// USER ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.get("/users/me", requireAuth, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, email, billing_address, order_count_30d, undo_count_30d, created_at
     FROM users WHERE id = $1`, [req.userId]
  );
  if (!rows.length) return res.status(404).json({ error: "Not found" });
  res.json(rows[0]);
});

// Ephemeral key for Stripe Issuing Elements (browser-side card display)
// Flow: browser creates nonce → POST here with nonce + txn_id → returns ephemeral_key_secret
// → browser calls stripe.retrieveIssuingCardDetails({ ephemeralKeySecret })
// PAN/CVC never touch this server.
app.post("/users/me/card-ephemeral-key", requireAuth, async (req, res) => {
  const { nonce, transaction_id } = req.body;
  if (!nonce || !transaction_id)
    return res.status(400).json({ error: "nonce and transaction_id required" });

  const { rows } = await db.query(
    `SELECT stripe_card_id FROM transactions WHERE id = $1 AND user_id = $2`,
    [transaction_id, req.userId]
  );
  if (!rows.length) return res.status(404).json({ error: "Transaction not found or not yours" });

  try {
    const ek = await stripe.ephemeralKeys.create(
      { issuing_card: rows[0].stripe_card_id, nonce },
      { apiVersion: "2023-10-16" }
    );
    res.json({ ephemeral_key_secret: ek.secret });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Payout method registration — full verification before saving
app.post("/users/me/payout-method", requireAuth, async (req, res) => {
  const { stripe_payment_method_id } = req.body;
  if (!stripe_payment_method_id || typeof stripe_payment_method_id !== "string")
    return res.status(400).json({ error: "stripe_payment_method_id required" });

  const { rows: userRows } = await db.query(
    `SELECT stripe_customer_id FROM users WHERE id = $1`, [req.userId]
  );
  if (!userRows.length) return res.status(404).json({ error: "User not found" });

  try {
    const pm = await stripe.paymentMethods.retrieve(stripe_payment_method_id);
    if (pm.customer !== userRows[0].stripe_customer_id)
      return res.status(403).json({ error: "PaymentMethod does not belong to this customer" });
    if (!["us_bank_account", "card"].includes(pm.type))
      return res.status(400).json({ error: "Must be type us_bank_account or card" });
    if (!pm.customer)
      return res.status(400).json({ error: "PaymentMethod is detached" });
    if (pm.type === "us_bank_account" && !pm.us_bank_account?.account_holder_type)
      return res.status(400).json({ error: "Bank account not fully verified" });
    if (pm.type === "card" && pm.card?.funding !== "debit")
      return res.status(400).json({ error: "Only debit cards are supported for payouts" });

    await db.query(
      `UPDATE users SET stripe_payout_method_id = $1 WHERE id = $2`,
      [stripe_payment_method_id, req.userId]
    );
    res.json({ success: true, payout_method_type: pm.type });
  } catch (err) {
    if (err.type === "StripeInvalidRequestError")
      return res.status(400).json({ error: "Invalid PaymentMethod ID" });
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// TRANSACTION ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.post("/transactions", requireAuth, async (req, res) => {
  const { amount_cents, tracking_number, carrier = "ups" } = req.body;
  if (!amount_cents || !tracking_number)
    return res.status(400).json({ error: "amount_cents and tracking_number required" });
  if (!Number.isInteger(amount_cents) || amount_cents < 100)
    return res.status(400).json({ error: "amount_cents must be an integer >= 100" });
  if (amount_cents > 100_000_00) // $100,000 ceiling
    return res.status(400).json({ error: "amount exceeds maximum" });

  // Fraud velocity check before any DB work
  const fraud = await checkFraudVelocity(req.userId);
  if (!fraud.allowed) {
    req.log.warn("Transaction blocked by fraud velocity", { user_id: req.userId, reason: fraud.reason });
    return res.status(429).json({ error: `Transaction blocked: ${fraud.reason}` });
  }

  const idempotencyKey = req.headers["idempotency-key"] || crypto.randomUUID();
  const client = await db.connect();
  try {
    await client.query("BEGIN");

    const dup = await client.query(
      `SELECT * FROM transactions WHERE idempotency_key = $1`, [idempotencyKey]
    );
    if (dup.rows.length) {
      await client.query("ROLLBACK");
      return res.json({ transaction: dup.rows[0], duplicate: true });
    }

    const { rows: userRows } = await client.query(
      `SELECT stripe_cardholder_id FROM users WHERE id = $1`, [req.userId]
    );
    if (!userRows.length || !userRows[0].stripe_cardholder_id)
      throw new Error("User cardholder not found — registration may be incomplete");

    // One card per transaction — this IS the auth binding mechanism
    const card = await stripe.issuing.cards.create({
      currency:   "usd",
      type:       "virtual",
      cardholder: userRows[0].stripe_cardholder_id,
      status:     "active",
      spending_controls: {
        spending_limits: [{
          amount:   Math.ceil(amount_cents * 1.10),
          interval: "per_authorization",
        }],
      },
    });

    await client.query(
      `INSERT INTO stripe_provisioning_log (type, stripe_id, user_email)
       SELECT 'card', $1, email FROM users WHERE id = $2`,
      [card.id, req.userId]
    );

    const { rows } = await client.query(
      `INSERT INTO transactions (user_id, amount_cents, tracking_number, carrier, stripe_card_id, idempotency_key)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.userId, amount_cents, tracking_number, carrier, card.id, idempotencyKey]
    );
    const txn = rows[0];

    await client.query(
      `UPDATE stripe_provisioning_log SET linked = TRUE WHERE stripe_id = $1`, [card.id]
    );
    // Increment 30d order count for velocity tracking
    await client.query(
      `UPDATE users SET order_count_30d = order_count_30d + 1 WHERE id = $1`, [req.userId]
    );
    await ledgerEntry(client, txn.id, req.userId, "hold", amount_cents,
      "Funds earmarked — awaiting authorization");

    // Enqueue AfterShip registration as a background job (non-blocking, inside transaction)
    await queue.enqueue(client, "register_tracking", { tracking_number, carrier, txn_id: txn.id });

    await client.query("COMMIT");
    req.log.info("Transaction created", { txn_id: txn.id, amount_cents });
    res.status(201).json({ transaction: txn, stripe_card_id: card.id });
  } catch (err) {
    await client.query("ROLLBACK");
    req.log.error("Transaction creation failed", { err: err.message });
    res.status(500).json({ error: "Failed to create transaction" });
  } finally { client.release(); }
});

app.get("/transactions/:id", requireAuth, requireOwnership, async (req, res) => {
  const { rows } = await db.query(`SELECT * FROM transactions WHERE id = $1`, [req.params.id]);
  res.json(rows[0]);
});

app.get("/transactions", requireAuth, async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = parseInt(req.query.offset) || 0;
  const { rows } = await db.query(
    `SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
    [req.userId, limit, offset]
  );
  res.json(rows);
});

// ─────────────────────────────────────────────────────────────────────────────
// UNDO ROUTE
// ─────────────────────────────────────────────────────────────────────────────

app.post("/transactions/:id/undo", requireAuth, undoLimiter, requireOwnership, async (req, res) => {
  const client = await db.connect();
  try {
    await client.query("BEGIN");

    const { rows } = await client.query(
      `SELECT t.*, u.stripe_customer_id, u.stripe_payout_method_id
       FROM transactions t JOIN users u ON u.id = t.user_id
       WHERE t.id = $1 FOR UPDATE`,
      [req.params.id]
    );
    const txn = rows[0];

    if (txn.status !== "delivered")
      throw Object.assign(new Error(`Cannot undo — status is '${txn.status}'`), { status: 400 });
    if (new Date() > new Date(txn.undo_deadline))
      throw Object.assign(new Error("Undo window has expired"), { status: 400 });

    await transitionStatus(client, txn.id, "delivered", "undone");
    await client.query(
      `UPDATE users SET undo_count_30d = undo_count_30d + 1 WHERE id = $1`, [txn.user_id]
    );
    await ledgerEntry(client, txn.id, txn.user_id, "undo_intent", txn.amount_cents,
      "User pressed UNDO — payout queued");

    // Payout is executed by the worker service — not inline here.
    // This keeps the API response fast and the payout retryable.
    const payoutStatus = txn.stripe_payout_method_id
      ? "pending" : "manual_review";

    await client.query(
      `UPDATE transactions SET payout_status = $1, updated_at = NOW() WHERE id = $2`,
      [payoutStatus, txn.id]
    );

    // Enqueue payout job — inside transaction so it only commits if undo commits
    await queue.enqueue(client, "execute_payout", { txn_id: txn.id }, { priority: 1 });

    await client.query("COMMIT");

    req.log.info("Undo accepted", { txn_id: txn.id, payout_status: payoutStatus });
    res.json({
      success:        true,
      refunded_cents: txn.amount_cents,
      payout_status:  payoutStatus,
      message:        payoutStatus === "pending"
        ? "Refund queued — funds typically arrive in 1-3 business days"
        : "Undo recorded — no payout method on file, flagged for manual review",
    });
  } catch (err) {
    await client.query("ROLLBACK");
    req.log.error("Undo failed", { err: err.message });
    res.status(err.status || 500).json({ error: err.message });
  } finally { client.release(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────────────────────────────────────
app.get("/health", async (_, res) => {
  const db_ok = await db.query("SELECT 1").then(() => true).catch(() => false);
  const { rows } = await db.query(
    `SELECT payout_status, COUNT(*) as count FROM transactions
     WHERE status = 'undone' GROUP BY payout_status`
  ).catch(() => ({ rows: [] }));
  const { rows: qRows } = await db.query(
    `SELECT status, COUNT(*) as count FROM job_queue GROUP BY status`
  ).catch(() => ({ rows: [] }));

  res.json({
    status:  "ok",
    service: "ontimepay-api",
    version: "5.0.0",
    db:      db_ok ? "connected" : "error",
    payouts: Object.fromEntries(rows.map(r => [r.payout_status, parseInt(r.count)])),
    jobs:    Object.fromEntries(qRows.map(r => [r.status, parseInt(r.count)])),
    ts:      new Date(),
  });
});

app.use((err, req, res, _next) => {
  req.log?.error("Unhandled error", { err: err.message });
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => log.info(`API service started`, { port: PORT }));
