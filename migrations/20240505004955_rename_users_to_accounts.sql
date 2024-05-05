BEGIN;

ALTER TABLE users RENAME TO accounts;

ALTER SEQUENCE users_id_seq RENAME TO accounts_id_seq;

ALTER INDEX users_pkey RENAME TO accounts_pkey;

ALTER INDEX users_created_at_ip_idx RENAME TO accounts_created_at_ip_hash_idx;

ALTER INDEX users_token_idx RENAME TO accounts_token_idx;

ALTER INDEX users_username_idx RENAME TO accounts_username_idx;

ALTER TABLE accounts RENAME CONSTRAINT users_username_key TO accounts_username_key;

ALTER TABLE accounts RENAME CONSTRAINT users_username_check TO accounts_username_check;

ALTER TABLE posts RENAME user_id TO account_id;

ALTER INDEX posts_user_id_idx RENAME TO posts_account_id_idx;

ALTER TABLE posts RENAME CONSTRAINT posts_user_id_fkey TO posts_account_id_fkey;

COMMIT;
