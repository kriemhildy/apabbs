BEGIN;

ALTER TABLE spam_words RENAME TO spam_terms;

ALTER TABLE spam_terms RENAME COLUMN word TO term;

COMMIT;
