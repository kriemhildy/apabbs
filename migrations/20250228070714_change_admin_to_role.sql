BEGIN;

CREATE TYPE account_role AS ENUM ('admin', 'mod', 'member', 'novice');

ALTER TABLE accounts ADD COLUMN role account_role NOT NULL DEFAULT 'novice';

UPDATE accounts SET role = 'admin' WHERE admin;

ALTER TABLE accounts DROP COLUMN admin;

COMMIT;
