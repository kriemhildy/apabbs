BEGIN;

CREATE TABLE reviews
(
    id serial PRIMARY KEY,
    account_id int NOT NULL references accounts(id) ON DELETE CASCADE,
    post_id int NOT NULL,
    status post_status NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX ON reviews(account_id);

CREATE INDEX ON reviews(post_id);

COMMIT;
