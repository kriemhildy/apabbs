BEGIN;

ALTER INDEX posts_created_at_ip_idx RENAME TO posts_created_at_ip_hash_idx;

COMMIT;

