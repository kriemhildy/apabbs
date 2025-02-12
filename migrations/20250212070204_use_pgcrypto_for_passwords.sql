-- this makes all accounts no longer able to log in,
-- however this is an alpha build and we are the only account.

BEGIN;

CREATE EXTENSION pgcrypto;

UPDATE accounts SET password_hash = '$2a$10$36z2.4BoWeXfVzV3p.12i.PyqoGcxOox9yKA0wwxPPHMdx5czhtoK'
    WHERE username = 'lungfish';

ALTER TABLE accounts ADD CHECK (length(password_hash) = 60);

COMMIT;
