BEGIN;

ALTER TABLE accounts ALTER password_hash TYPE text;

ALTER TABLE accounts ALTER password_salt TYPE text;

ALTER TABLE accounts ALTER ip_hash TYPE text;

ALTER TABLE accounts ADD CHECK(length(ip_hash) = 64);

ALTER TABLE accounts DROP CONSTRAINT accounts_username_check;

ALTER TABLE accounts ADD CHECK(length(username) >= 4 AND length(username) <= 16);

ALTER TABLE bans ALTER ip_hash TYPE text;

ALTER TABLE bans ADD CHECK(length(ip_hash) = 64);

ALTER TABLE posts ALTER body TYPE text;

ALTER TABLE posts ADD CHECK(length(body) <= 10000);

ALTER TABLE posts ALTER username TYPE citext;

ALTER TABLE posts ADD CHECK (length(username) >= 4 AND length(username) <= 16);

ALTER TABLE posts ALTER anon_hash TYPE text;

ALTER TABLE posts ADD CHECK(length(anon_hash) = 8);

ALTER TABLE posts ALTER ip_hash TYPE text;

ALTER TABLE posts ADD CHECK(length(ip_hash) = 64);

ALTER TABLE posts ALTER media_file_name TYPE text;

ALTER TABLE posts ADD CHECK(length(media_file_name) >= 4 AND length(media_file_name) <= 255);

ALTER TABLE posts ALTER media_mime_type TYPE text;

ALTER TABLE posts ADD CHECK(length(media_mime_type) >= 9 AND length(media_mime_type) <= 24);

COMMIT;
