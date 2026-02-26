-- Rename constraints and indexes to remove "_opt" from their names
ALTER TABLE posts
    RENAME CONSTRAINT posts_compat_video_opt_check TO posts_compat_video_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_ip_hash_opt_check TO posts_ip_hash_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_media_filename_opt_check TO posts_media_filename_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_media_height_opt_check TO posts_media_height_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_media_mime_type_opt_check TO posts_media_mime_type_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_media_poster_opt_check TO posts_media_poster_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_media_width_opt_check TO posts_media_width_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_thumb_filename_opt_check TO posts_thumb_filename_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_thumb_height_opt_check TO posts_thumb_height_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_thumb_width_opt_check TO posts_thumb_width_check;
ALTER TABLE posts
    RENAME CONSTRAINT posts_account_id_opt_fkey TO posts_account_id_fkey;
ALTER INDEX posts_account_id_opt_idx
    RENAME TO posts_account_id_idx;
ALTER INDEX posts_created_at_ip_hash_opt_idx
    RENAME TO posts_created_at_ip_hash_idx;
ALTER INDEX posts_session_token_opt_idx
    RENAME TO posts_session_token_idx;
ALTER INDEX accounts_created_at_ip_hash_opt_idx
    RENAME TO accounts_created_at_ip_hash_idx;
ALTER TABLE accounts
    RENAME CONSTRAINT accounts_ip_hash_opt_check TO accounts_ip_hash_check;
ALTER INDEX bans_admin_account_id_opt_idx
    RENAME TO bans_admin_account_id_idx;
ALTER INDEX bans_banned_account_id_opt_idx
    RENAME TO bans_banned_account_id_idx;
ALTER INDEX bans_expires_at_banned_account_id_opt_ip_hash_idx
    RENAME TO bans_expires_at_banned_account_id_ip_hash_idx;
ALTER TABLE bans
    RENAME CONSTRAINT bans_admin_account_id_opt_fkey TO bans_admin_account_id_fkey;
