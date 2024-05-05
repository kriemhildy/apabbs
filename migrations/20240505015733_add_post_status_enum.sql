BEGIN;

CREATE TYPE post_status AS ENUM ('pending', 'approved', 'rejected');

ALTER TABLE posts ALTER status DROP DEFAULT;

ALTER TABLE posts ALTER status TYPE post_status USING cast(status as post_status);

ALTER TABLE posts ALTER status SET DEFAULT 'pending';

COMMIT;
