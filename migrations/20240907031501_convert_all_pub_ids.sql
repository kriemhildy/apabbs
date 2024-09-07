BEGIN;

CREATE FUNCTION random_alphanumeric(len integer) RETURNS text AS $$
    SELECT string_agg(
        substr(
            characters, (
                random() * length(characters) + 1
            )::integer,
            1
        ),
        ''
    ) AS random_word FROM (
        VALUES('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    ) AS symbols(characters)
    JOIN generate_series(1, len) ON 1 = 1;
$$ LANGUAGE SQL;

UPDATE posts SET pub_id = random_alphanumeric(10) WHERE length(pub_id) = 36;

ALTER TABLE posts ALTER COLUMN pub_id TYPE char(10);

COMMIT;
