BEGIN;

ALTER TABLE bans RENAME TO old_bans;

ALTER TABLE old_bans RENAME CONSTRAINT bans_pkey TO old_bans_pkey;
ALTER TABLE old_bans RENAME CONSTRAINT bans_ip_hash_check TO old_bans_ip_hash_check;

CREATE TABLE bans (
    id serial PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '1 mon',
    ip_hash text NOT NULL,
    banned_account_id int,
    admin_account_id int REFERENCES accounts(id),
    CHECK(length(ip_hash) = 64)
);

INSERT INTO bans (ip_hash, created_at, expires_at)
    SELECT ip_hash, expires_at - interval '1 mon' AS created_at, expires_at
    FROM old_bans ORDER BY expires_at;

DROP TABLE old_bans;


UPDATE bans SET admin_account_id = (
    SELECT id FROM accounts WHERE role = 'admin' ORDER BY id LIMIT 1
) WHERE admin_account_id IS NULL;

CREATE INDEX ON bans (created_at);
CREATE INDEX on bans (expires_at, banned_account_id, ip_hash);
CREATE INDEX ON bans (banned_account_id);
CREATE INDEX ON bans (ip_hash);
CREATE INDEX ON bans (admin_account_id);

COMMIT;
