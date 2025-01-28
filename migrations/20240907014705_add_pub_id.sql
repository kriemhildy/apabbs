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

-- ALTER TABLE posts DROP COLUMN uuid;

ALTER TABLE posts ADD COLUMN pub_id text DEFAULT alphanumeric(16) UNIQUE NOT NULL;

CREATE UNIQUE INDEX ON posts(pub_id);

ALTER TABLE posts ADD CHECK (length(pub_id) = 16);

COMMIT;
