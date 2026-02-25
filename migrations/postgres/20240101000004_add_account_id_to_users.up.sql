-- Add account_id to users to support multi-org/multi-tenant deployments.
-- Email uniqueness is now scoped per account, so two different accounts can
-- have users with the same email address.

ALTER TABLE users ADD COLUMN account_id VARCHAR(36) NOT NULL DEFAULT '';

-- Drop the global email unique constraint
ALTER TABLE users DROP CONSTRAINT users_email_key;

-- Add compound unique constraint: email must be unique within an account
ALTER TABLE users ADD CONSTRAINT users_email_account_id_key UNIQUE (email, account_id);

-- Replace the email-only index with a compound one used for login lookups
DROP INDEX IF EXISTS idx_users_email;
CREATE INDEX idx_users_email_account_id ON users(email, account_id);
