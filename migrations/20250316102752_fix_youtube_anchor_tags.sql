UPDATE posts SET body = regexp_replace(
        body,
        'alt="Youtube ([\w\-]+)"></div>',
        'alt="YouTube \1"></a></div>'
    )
    WHERE body LIKE '%alt="Youtube%';
