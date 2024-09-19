BEGIN;

ALTER TABLE accounts ADD CONSTRAINT accounts_token_key UNIQUE (token);

COMMIT;
