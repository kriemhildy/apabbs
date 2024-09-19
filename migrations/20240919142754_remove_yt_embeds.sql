BEGIN;

UPDATE posts
    SET body = regexp_replace (
        body,
        '<iframe class="short"[^>]*src="https://www.youtube.com/embed/([^"]*)"[^>]*></iframe>',
        '<a href="http://www.youtube.com/shorts/\1" target="_blank">http://www.youtube.com/shorts/\1</a>'
    );

UPDATE posts
    SET body = regexp_replace (
        body,
        '<iframe[^>]*src="https://www.youtube.com/embed/([^"]*)"[^>]*></iframe>',
        '<a href="http://www.youtube.com/watch?v=\1" target="_blank">http://www.youtube.com/watch?v=\1</a>'
    );

COMMIT;
