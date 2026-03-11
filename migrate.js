// migrate.js — runs at deploy time, creates all tables
// Usage: node migrate.js
require("dotenv").config();
const { Pool } = require("pg");

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function migrate() {
  console.log("Running migration...");
  await db.query(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    CREATE TABLE IF NOT EXISTS users (
      id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email                     TEXT UNIQUE NOT NULL,
      password_hash             TEXT NOT NULL,
      stripe_customer_id        TEXT UNIQUE,
      stripe_cardholder_id      TEXT UNIQUE,
      stripe_payout_method_id   TEXT,
      billing_address           JSONB NOT NULL,
      order_count_30d           INTEGER NOT NULL DEFAULT 0,
      undo_count_30d            INTEGER NOT NULL DEFAULT 0,
      is_active                 BOOLEAN NOT NULL DEFAULT TRUE,
      suspended_at              TIMESTAMPTZ,
      suspension_reason         TEXT,
      last_login_at             TIMESTAMPTZ,
      login_count               INTEGER NOT NULL DEFAULT 0,
      refresh_family            UUID DEFAULT gen_random_uuid(),
      created_at                TIMESTAMPTZ DEFAULT NOW(),
      updated_at                TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash  TEXT NOT NULL UNIQUE,
      family      UUID NOT NULL,
      expires_at  TIMESTAMPTZ NOT NULL,
      revoked     BOOLEAN NOT NULL DEFAULT FALSE,
      revoked_at  TIMESTAMPTZ,
      user_agent  TEXT,
      ip_address  TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id             UUID NOT NULL REFERENCES users(id),
      amount_cents        INTEGER NOT NULL CHECK (amount_cents > 0),
      fee_cents           INTEGER NOT NULL DEFAULT 700,
      status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','authorized','funded','delivered','undone','settled','failed')),
      payout_status       TEXT NOT NULL DEFAULT 'none'
                            CHECK (payout_status IN ('none','pending','posted','failed','returned','canceled','manual_review')),
      payout_attempts     INTEGER NOT NULL DEFAULT 0,
      payout_last_error   TEXT,
      payout_succeeded_at TIMESTAMPTZ,
      stripe_payout_id    TEXT UNIQUE,
      stripe_card_id      TEXT UNIQUE NOT NULL,
      stripe_auth_id      TEXT UNIQUE,
      tracking_number     TEXT,
      carrier             TEXT,
      delivered_at        TIMESTAMPTZ,
      undo_deadline       TIMESTAMPTZ,
      fraud_score         SMALLINT,
      flagged_for_review  BOOLEAN NOT NULL DEFAULT FALSE,
      idempotency_key     TEXT UNIQUE,
      created_at          TIMESTAMPTZ DEFAULT NOW(),
      updated_at          TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ledger (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      transaction_id  UUID REFERENCES transactions(id),
      user_id         UUID NOT NULL REFERENCES users(id),
      type            TEXT NOT NULL,
      amount_cents    INTEGER NOT NULL,
      note            TEXT,
      meta            JSONB DEFAULT '{}',
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS job_queue (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      type        TEXT NOT NULL,
      payload     JSONB NOT NULL DEFAULT '{}',
      status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','processing','done','dead')),
      priority    SMALLINT NOT NULL DEFAULT 5,
      attempts    INTEGER NOT NULL DEFAULT 0,
      last_error  TEXT,
      run_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS stripe_provisioning_log (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      type        TEXT NOT NULL,
      stripe_id   TEXT NOT NULL UNIQUE,
      linked      BOOLEAN NOT NULL DEFAULT FALSE,
      user_email  TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS processed_events (
      event_id     TEXT PRIMARY KEY,
      processed_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS fraud_signals (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id     UUID NOT NULL REFERENCES users(id),
      signal_type TEXT NOT NULL,
      detail      TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_txn_user         ON transactions(user_id);
    CREATE INDEX IF NOT EXISTS idx_txn_status       ON transactions(status);
    CREATE INDEX IF NOT EXISTS idx_txn_tracking     ON transactions(tracking_number);
    CREATE INDEX IF NOT EXISTS idx_txn_auth         ON transactions(stripe_auth_id);
    CREATE INDEX IF NOT EXISTS idx_txn_card         ON transactions(stripe_card_id);
    CREATE INDEX IF NOT EXISTS idx_ledger_txn       ON ledger(transaction_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_user     ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_job_dequeue      ON job_queue(type, priority, run_at) WHERE status = 'pending';
    CREATE INDEX IF NOT EXISTS idx_processed_ts     ON processed_events(processed_at);
  `);
  console.log("✅ Migration complete");
  await db.end();
}

migrate().catch(err => {
  console.error("Migration failed:", err.message);
  process.exit(1);
});
