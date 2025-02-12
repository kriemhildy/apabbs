BEGIN;

ALTER TABLE accounts DROP password_salt;

COMMIT;
