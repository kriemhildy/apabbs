BEGIN;

ALTER TABLE spam_words
DROP CONSTRAINT spam_words_word_check;

ALTER TABLE spam_words
ADD CHECK (length(word) BETWEEN 3 and 256);

COMMIT;
