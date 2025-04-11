-- this gives all accounts the password 'H3qwYKEj4zsB',
-- however this is an alpha build and we are the only account.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

UPDATE accounts SET password_hash = crypt('H3qwYKEj4zsB', gen_salt('bf', 10));

ALTER TABLE accounts ADD CHECK (length(password_hash) = 60);

COMMIT;
