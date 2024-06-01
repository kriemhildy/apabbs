BEGIN;

ALTER TABLE bans ADD expires_at timestamptz NOT NULL DEFAULT now() + interval '1 month';

ALTER TABLE bans DROP CONSTRAINT bans_pkey;

ALTER TABLE bans ADD PRIMARY KEY (ip_hash, expires_at);

COMMIT;
