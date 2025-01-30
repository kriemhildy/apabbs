BEGIN;

CREATE EXTENSION pgcrypto;

CREATE OR REPLACE FUNCTION alphanumeric(size INT) RETURNS TEXT AS $$
DECLARE
  characters TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  bytes BYTEA := gen_random_bytes(size);
  l INT := length(characters);
  i INT := 0;
  output TEXT := '';
BEGIN
  WHILE i < size LOOP
    output := output || substr(characters, get_byte(bytes, i) % l + 1, 1);
    i := i + 1;
  END LOOP;
  RETURN output;
END;
$$ LANGUAGE plpgsql VOLATILE;

ALTER TABLE posts ADD COLUMN pub_id text DEFAULT alphanumeric(16) UNIQUE NOT NULL;

CREATE UNIQUE INDEX ON posts(pub_id);

ALTER TABLE posts ADD CHECK (length(pub_id) = 16);

-- move media files

-- this must be defined by the superuser in the APABBS database
-- CREATE EXTENSION plpython3u;
-- CREATE FUNCTION move_media_dir (posts posts[]) RETURNS integer AS $$
-- import os
-- import shutil

-- MEDIA_DIR = 'pub/media/'

-- print("move_media_dir call for {} posts".format(len(posts)))
-- for post in posts:
--     uuid = post['uuid']
--     pub_id = post['pub_id']

--     uuid_dir = os.path.join(MEDIA_DIR, uuid)
--     pub_id_dir = os.path.join(MEDIA_DIR, pub_id)

--     if os.path.exists(uuid_dir):
--         #shutil.move(uuid_dir, pub_id_dir)
--         print("Moved media dir from {} to {}".format(uuid, pub_id))
-- $$ LANGUAGE plpython3u;

-- SELECT move_media_dir(select array(row(posts.*) from posts));


-- single post version
-- CREATE OR REPLACE FUNCTION move_media_dir (post posts) RETURNS integer AS $$
-- import os
-- import shutil

-- MEDIA_DIR = 'pub/media/'

-- uuid = post['uuid']
-- pub_id = post['pub_id']

-- print("move_media_dir call for post {} -> {}".format(uuid, pub_id))
-- uuid_dir = os.path.join(MEDIA_DIR, uuid)
-- pub_id_dir = os.path.join(MEDIA_DIR, pub_id)

-- if os.path.exists(uuid_dir):
--     #shutil.move(uuid_dir, pub_id_dir)
--     print("Moved media dir from {} to {}".format(uuid, pub_id))
-- $$ LANGUAGE plpython3u;

-- SELECT move_media_dir(p) FROM posts p;

-- cleanup

-- ALTER TABLE posts DROP COLUMN uuid;

-- can only be done by superuser
-- DROP FUNCTION move_media_dir;

COMMIT;
