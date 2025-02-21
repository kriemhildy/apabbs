BEGIN;

UPDATE posts SET body = REPLACE(body, 'src="/youtube.svg">', 'src="/youtube.svg" alt>')
    WHERE body LIKE '%src="/youtube.svg">%';

COMMIT;
