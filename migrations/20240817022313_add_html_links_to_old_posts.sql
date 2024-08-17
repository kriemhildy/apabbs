UPDATE posts SET body = regexp_replace(body, '(https?://\S+)', '<a href="\1" target="_blank">\1</a>', 'g');
