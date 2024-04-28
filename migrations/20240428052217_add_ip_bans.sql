BEGIN;

CREATE TABLE bans (
    ip varchar NOT NULL PRIMARY KEY
);

ALTER TABLE posts ALTER ip TYPE varchar;

ALTER TABLE users ALTER ip TYPE varchar;

CREATE INDEX ON posts (created_at, ip);

CREATE INDEX ON users (created_at, ip);

COMMIT;
