-- Accounts table: stores named, uniquely-identified tenants.
-- The id (UUID) is the opaque identifier used in API calls (X-Account-ID header).
-- The name is a human-readable unique slug chosen at signup.

CREATE TABLE accounts (
    id         VARCHAR(36)  PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_accounts_name ON accounts(name);
