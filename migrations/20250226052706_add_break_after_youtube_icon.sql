UPDATE posts SET body = REPLACE(body, '<img src="/youtube.svg" alt></a>', '<img src="/youtube.svg" alt></a><br>')
    WHERE body LIKE '%<img src="/youtube.svg" alt></a>%';
