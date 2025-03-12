BEGIN;

UPDATE posts SET body = REPLACE(body, '<a class="youtube"', '<div class="youtube"><a') WHERE body LIKE '%<a class="youtube"%';

UPDATE posts SET body = regexp_replace(body, 'alt="YouTube ([\w\-]+)">', 'alt="Youtube \1"></div>') WHERE body LIKE '%alt="YouTube%';

COMMIT;
