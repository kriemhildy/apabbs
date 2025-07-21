UPDATE posts SET body = replace(replace(body, '&quot;', '"'), '&apos;', '''')
WHERE body LIKE '%&quot;%' OR body LIKE '%&apos;%';
