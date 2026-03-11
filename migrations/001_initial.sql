/**
 * migrations/001_initial.sql
 * Run once against a fresh database.
 * Apply with: psql $DATABASE_URL -f migrations/001_initial.sql
 * Or use a migration runner like db-migrate, flyway, or golang-migrate.
 */

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email                     TEXT UNIQUE NOT NULL,
  password_hash             TEXT NOT NULL,
  stripe_customer_id        TEXT UNIQUE,
  stripe_cardholder_id      TEXT UNIQUE,
  -- Payout destination stored at onboarding. Never supplied by client at undo time.
  stripe_payout_method_id   TEXT,
  billing_address           JSONB NOT NULL,
  -- Fraud / velocity controls
  order_count_30d           INTEGER NOT NULL DEFAULT 0,
  undo_count_30d            INTEGER NOT NULL DEFAULT 0,
  is_active                 BOOLEAN NOT NULL DEFAULT TRUE,
  suspended_at              TIMESTAMPTZ,
  suspension_reason         TEXT,
  -- Session audit
  last_login_at             TIMESTAMPTZ,
  login_count               INTEGER NOT NULL DEFAULT 0,
  -- Refresh token family tracking (reuse detection)
  refresh_family            UUID DEFAULT gen_random_uuid(),
  created_at                TIMESTAMPTZ DEFAULT NOW(),
  updated_at                TIMESTAMPTZ DEFAULT NOW()
);

-- ── Refresh tokens ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  family      UUID NOT NULL,              -- matches users.refresh_family
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at  TIMESTAMPTZ,
  user_agent  TEXT,
  ip_address  INET,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Transactions ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL REFERENCES users(id),
  amount_cents        INTEGER NOT NULL CHECK (amount_cents > 0),
  fee_cents           INTEGER NOT NULL DEFAULT 700,

  -- Main lifecycle status
  status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','authorized','funded','delivered',
                                          'undone','settled','failed')),

  -- Payout lifecycle — separate from undo intent
  -- Mirrors Stripe Treasury OutboundPayment states
  payout_status       TEXT NOT NULL DEFAULT 'none'
                        CHECK (payout_status IN
                          ('none','pending','posted','failed','returned','canceled','manual_review')),
  payout_attempts     INTEGER NOT NULL DEFAULT 0,
  payout_last_error   TEXT,
  payout_succeeded_at TIMESTAMPTZ,
  stripe_payout_id    TEXT UNIQUE,

  -- One dedicated virtual card per transaction (the auth binding mechanism)
  stripe_card_id      TEXT UNIQUE NOT NULL,
  stripe_auth_id      TEXT UNIQUE,

  -- Shipping
  tracking_number     TEXT,
  carrier             TEXT,
  delivered_at        TIMESTAMPTZ,
  undo_deadline       TIMESTAMPTZ,

  -- Fraud flags
  fraud_score         SMALLINT,
  flagged_for_review  BOOLEAN NOT NULL DEFAULT FALSE,

  idempotency_key     TEXT UNIQUE,
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ── Append-only ledger ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ledger (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id  UUID REFERENCES transactions(id),
  user_id         UUID NOT NULL REFERENCES users(id),
  type            TEXT NOT NULL,
  amount_cents    INTEGER NOT NULL,
  note            TEXT,
  meta            JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW()
  -- NO UPDATE, NO DELETE
);

-- ── Job queue (Postgres-backed, SKIP LOCKED) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS job_queue (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type        TEXT NOT NULL,
  payload     JSONB NOT NULL DEFAULT '{}',
  status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','processing','done','dead')),
  priority    SMALLINT NOT NULL DEFAULT 5,   -- lower = higher priority
  attempts    INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT,
  run_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Stripe provisioning log (orphan recovery) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS stripe_provisioning_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type        TEXT NOT NULL,   -- 'customer' | 'cardholder' | 'card'
  stripe_id   TEXT NOT NULL UNIQUE,
  linked      BOOLEAN NOT NULL DEFAULT FALSE,
  user_email  TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Processed webhook events (idempotency) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS processed_events (
  event_id     TEXT PRIMARY KEY,
  processed_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Fraud velocity table ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fraud_signals (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id),
  signal_type TEXT NOT NULL,   -- 'high_undo_rate' | 'rapid_orders' | 'amount_spike' etc.
  detail      TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── INDEXES ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_txn_user          ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_txn_status        ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_txn_tracking      ON transactions(tracking_number);
CREATE INDEX IF NOT EXISTS idx_txn_auth          ON transactions(stripe_auth_id);
CREATE INDEX IF NOT EXISTS idx_txn_card          ON transactions(stripe_card_id);
-- Partial index: only rows that need payout action (hot path for worker)
CREATE INDEX IF NOT EXISTS idx_txn_payout_work
  ON transactions(payout_status, updated_at)
  WHERE payout_status IN ('pending','failed');
-- Partial index: settlement candidates
CREATE INDEX IF NOT EXISTS idx_txn_settle
  ON transactions(undo_deadline)
  WHERE status = 'delivered';
CREATE INDEX IF NOT EXISTS idx_ledger_txn        ON ledger(transaction_id);
CREATE INDEX IF NOT EXISTS idx_ledger_user       ON ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_refresh_user      ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family    ON refresh_tokens(family);
CREATE INDEX IF NOT EXISTS idx_job_dequeue
  ON job_queue(type, priority, run_at)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_prov_unlinked
  ON stripe_provisioning_log(created_at)
  WHERE linked = FALSE;
CREATE INDEX IF NOT EXISTS idx_processed_events_ts ON processed_events(processed_at);
CREATE INDEX IF NOT EXISTS idx_fraud_user        ON fraud_signals(user_id, created_at DESC);
