--                                            Table "public.posts"
--        Column        |           Type           | Collation | Nullable |              Default
-- ---------------------+--------------------------+-----------+----------+-----------------------------------
--  id                  | integer                  |           | not null | nextval('posts_id_seq'::regclass)
--  body                | text                     |           | not null |
--  account_id_opt      | integer                  |           |          |
--  created_at          | timestamp with time zone |           | not null | now()
--  status              | post_status              |           | not null | 'pending'::post_status
--  session_token_opt   | uuid                     |           |          |
--  hidden              | boolean                  |           | not null | false
--  ip_hash_opt         | text                     |           |          |
--  media_filename_opt  | text                     |           |          |
--  media_category_opt  | media_category           |           |          |
--  media_mime_type_opt | text                     |           |          |
--  thumb_filename_opt  | text                     |           |          |
--  key                 | text                     |           | not null |
--  youtube             | boolean                  |           | not null | false
--  intro_limit_opt     | integer                  |           |          |
--  media_width_opt     | integer                  |           |          |
--  media_height_opt    | integer                  |           |          |
--  thumb_width_opt     | integer                  |           |          |
--  thumb_height_opt    | integer                  |           |          |
--  video_poster_opt    | text                     |           |          |
--  compat_video_opt    | text                     |           |          |
BEGIN;

ALTER TABLE posts RENAME account_id_opt TO account_id;
ALTER TABLE posts RENAME session_token_opt TO session_token;
ALTER TABLE posts RENAME ip_hash_opt TO ip_hash;
ALTER TABLE posts RENAME media_filename_opt TO media_filename;
ALTER TABLE posts RENAME media_category_opt TO media_category;
ALTER TABLE posts RENAME media_mime_type_opt TO media_mime_type;
ALTER TABLE posts RENAME thumb_filename_opt TO thumb_filename;
ALTER TABLE posts RENAME intro_limit_opt TO intro_limit;
ALTER TABLE posts RENAME media_width_opt TO media_width;
ALTER TABLE posts RENAME media_height_opt TO media_height;
ALTER TABLE posts RENAME thumb_width_opt TO thumb_width;
ALTER TABLE posts RENAME thumb_height_opt TO thumb_height;
ALTER TABLE posts RENAME video_poster_opt TO video_poster;
ALTER TABLE posts RENAME compat_video_opt TO compat_video;

--                                         Table "public.accounts"
--     Column     |           Type           | Collation | Nullable |               Default
-- ---------------+--------------------------+-----------+----------+--------------------------------------
--  id            | integer                  |           | not null | nextval('accounts_id_seq'::regclass)
--  created_at    | timestamp with time zone |           | not null | now()
--  token         | uuid                     |           | not null | gen_random_uuid()
--  username      | citext                   |           | not null |
--  password_hash | text                     |           | not null |
--  ip_hash_opt   | text                     |           |          |
--  time_zone     | text                     |           | not null | 'UTC'::text
--  role          | account_role             |           | not null | 'novice'::account_role

ALTER TABLE accounts RENAME ip_hash_opt TO ip_hash;

--                                             Table "public.bans"
--         Column         |           Type           | Collation | Nullable |             Default
-- -----------------------+--------------------------+-----------+----------+----------------------------------
--  id                    | integer                  |           | not null | nextval('bans_id_seq'::regclass)
--  created_at            | timestamp with time zone |           | not null | now()
--  expires_at            | timestamp with time zone |           | not null | now() + '1 mon'::interval
--  ip_hash               | text                     |           | not null |
--  banned_account_id_opt | integer                  |           |          |
--  admin_account_id_opt  | integer                  |           |          |

ALTER TABLE bans RENAME banned_account_id_opt TO banned_account_id;
ALTER TABLE bans RENAME admin_account_id_opt TO admin_account_id;

COMMIT;
