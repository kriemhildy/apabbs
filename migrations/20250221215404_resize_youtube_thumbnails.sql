BEGIN;

UPDATE posts SET body = REPLACE(
    REPLACE(
        REPLACE(body, 'mqdefault', 'maxresdefault'),
        'width="320" height="180" ',
        ''
    ),
    '<a href="https://www.youtube.com',
    '<img class="youtube" src="/youtube.svg"><a href="https://www.youtube.com'
) WHERE body LIKE '%youtube.com%';
