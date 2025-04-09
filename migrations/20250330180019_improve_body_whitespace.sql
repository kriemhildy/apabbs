BEGIN;

UPDATE posts SET body = regexp_replace(
    body,
    '<div class="youtube"><div class="logo"><a href="([^"]+)"><img src="/youtube\.svg" alt></a>' ||
    '</div><a href="([^"]+)"><img src="([^"]+)" alt="([^"]+)"></a></div>',
    '<div class="youtube">' || E'\n' ||
    '    <div class="logo">' || E'\n' ||
    '        <a href="\1">' ||
    '<img src="/youtube.svg" alt>' ||
    '</a>' || E'\n' ||
    '    </div>' || E'\n' ||
    '    <a href="\2">' ||
    '<img src="\3" alt="\4">' ||
    '</a>' || E'\n' ||
    '</div>',
    'g'
) WHERE body LIKE '%<div class="youtube">%';

UPDATE posts SET body = replace(
    body,
    '<br>',
    E'<br>\n'
) WHERE body LIKE '%<br>%';

COMMIT;
