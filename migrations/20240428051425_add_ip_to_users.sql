BEGIN;

ALTER TABLE users ADD ip inet;

UPDATE users SET ip = '::1';

ALTER TABLE users ALTER ip SET NOT NULL;

COMMIT;
