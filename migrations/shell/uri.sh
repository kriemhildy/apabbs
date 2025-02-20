psql $DATABASE_URL \
    -c "SELECT uuid, uri FROM posts WHERE media_file_name IS NOT NULL" \
    --field-separator=' ' \
    --no-align \
    --quiet \
    --tuples-only \
| while read uuid uri; do
    if [ -d "pub/media/$uuid" ]; then
        echo "Moving media from $uuid to $uri"
        mv "pub/media/$uuid" "pub/media/$uri"
    fi
done
