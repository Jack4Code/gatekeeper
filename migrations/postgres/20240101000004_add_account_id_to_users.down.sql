-- Rollback account_id migration

DROP INDEX IF EXISTS idx_users_email_account_id;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_account_id_key;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
CREATE INDEX idx_users_email ON users(email);
ALTER TABLE users DROP COLUMN IF EXISTS account_id;
