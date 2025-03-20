BEGIN;

ALTER TABLE posts RENAME COLUMN account_id TO account_id_opt;
ALTER INDEX posts_account_id_idx RENAME TO posts_account_id_opt_idx;
ALTER TABLE posts RENAME CONSTRAINT posts_account_id_fkey
    TO posts_account_id_opt_fkey;
ALTER TABLE posts RENAME COLUMN session_token TO session_token_opt;
ALTER INDEX posts_session_token_idx RENAME TO posts_session_token_opt_idx;
ALTER TABLE posts RENAME COLUMN media_file_name TO media_file_name_opt;
ALTER TABLE posts RENAME CONSTRAINT posts_media_file_name_check
    TO posts_media_file_name_opt_check;
ALTER TABLE posts RENAME COLUMN media_category TO media_category_opt;
ALTER TABLE posts RENAME COLUMN media_mime_type TO media_mime_type_opt;
ALTER TABLE posts RENAME CONSTRAINT posts_media_mime_type_check
    TO posts_media_mime_type_opt_check;
ALTER TABLE posts RENAME COLUMN ip_hash TO ip_hash_opt;
ALTER INDEX posts_created_at_ip_hash_idx RENAME TO posts_created_at_ip_hash_opt_idx;
ALTER TABLE posts RENAME CONSTRAINT posts_ip_hash_check
    TO posts_ip_hash_opt_check;
ALTER TABLE posts RENAME COLUMN thumbnail_file_name TO thumbnail_file_name_opt;
ALTER TABLE posts RENAME CONSTRAINT posts_thumbnail_file_name_check
    TO posts_thumbnail_file_name_opt_check;

ALTER TABLE accounts RENAME COLUMN ip_hash TO ip_hash_opt;
ALTER TABLE accounts RENAME CONSTRAINT accounts_ip_hash_check
    TO accounts_ip_hash_opt_check;
ALTER INDEX accounts_created_at_ip_hash_idx RENAME TO accounts_created_at_ip_hash_opt_idx;

ALTER TABLE bans RENAME COLUMN banned_account_id TO banned_account_id_opt;
ALTER INDEX bans_banned_account_id_idx RENAME TO bans_banned_account_id_opt_idx;
ALTER INDEX bans_expires_at_banned_account_id_ip_hash_idx
    RENAME TO bans_expires_at_banned_account_id_opt_ip_hash_idx;
ALTER TABLE bans RENAME COLUMN admin_account_id TO admin_account_id_opt;
ALTER INDEX bans_admin_account_id_idx RENAME TO bans_admin_account_id_opt_idx;
ALTER TABLE bans RENAME CONSTRAINT bans_admin_account_id_fkey
    TO bans_admin_account_id_opt_fkey;

COMMIT;
