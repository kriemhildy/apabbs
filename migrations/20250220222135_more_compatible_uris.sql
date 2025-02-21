BEGIN;

CREATE FUNCTION alphanumeric(size INT) RETURNS TEXT AS $$
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

ALTER TABLE posts RENAME COLUMN uri TO old_uri;

ALTER TABLE posts DROP CONSTRAINT posts_uri_key;
ALTER TABLE posts DROP CONSTRAINT posts_uri_check;

ALTER TABLE posts ADD COLUMN uri text DEFAULT alphanumeric(8) UNIQUE NOT NULL;

ALTER TABLE posts ADD CHECK (uri ~ '^[A-Za-z0-9]+$' AND length(uri) = 8);

COMMIT;
