BEGIN;

UPDATE posts SET body = regexp_replace(
    body,
    '<div class="youtube"><div class="logo"><a href="([^"]+)"><img src="/youtube\.svg" alt></a>' ||
    '</div><a href="([^"]+)"><img src="([^"]+)" alt="([^"]+)"></a></div>',
    '<div class="youtube">' || E'\n' ||
    '    <div class="logo">' || E'\n' ||
    '        <a href="\1">' || E'\n' ||
    '            <img src="/youtube.svg" alt>' || E'\n' ||
    '        </a>' || E'\n' ||
    '    </div>' || E'\n' ||
    '    <a href="\2">' || E'\n' ||
    '        <img src="\3" alt="\4">' || E'\n' ||
    '    </a>' || E'\n' ||
    '</div>',
    'g'
) WHERE body LIKE '%<div class="youtube">%';

UPDATE posts SET body = replace(
    replace(
        body,
        '<br>',
        E'\n<br>\n'
    ),
    E'\n\n',
    E'\n'
) WHERE body LIKE '%<br>%';

UPDATE posts SET body = regexp_replace(
    body,
    '([\.!\?,;:\-' || E'\u2013\u2014' || ']["''' || E'\u201d\u2019' || ']?) +',
    '\1' || E'\n',
    'g'
) WHERE body ~ concat('[\.!\?]["''', E'\u201d\u2019', ']? +');

COMMIT;
