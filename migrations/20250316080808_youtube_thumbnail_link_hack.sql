-- this file was added much later than its timestamp as a hack so that it runs prior to the
-- following migration.
-- before, this code was executed via a bash script that downloaded youtube thumbnails which was
-- manually run in production before we created the rust migration system.

UPDATE posts SET body =
    regexp_replace(
        body,
        '<img src="https://img.youtube.com/vi/([\w\-]{11})/(\w+).jpg',
        '<img src="/youtube/\1/\2.jpg', 'g'
    )
    WHERE body LIKE '%<img src="https://img.youtube.com/vi%';
