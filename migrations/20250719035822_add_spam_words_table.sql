CREATE TABLE spam_words (
    id serial PRIMARY KEY,
    word text NOT NULL UNIQUE CHECK (length(word) BETWEEN 4 AND 32)
);
