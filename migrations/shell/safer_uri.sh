psql $DATABASE_URL \
    -c "SELECT old_uri, uri FROM posts WHERE media_file_name IS NOT NULL" \
    --field-separator=' ' \
    --no-align \
    --quiet \
    --tuples-only \
| while read old_uri uri; do
    if [ -d "pub/media/$old_uri" ]; then
        echo "Moving media from $old_uri to $uri"
        mv "pub/media/$old_uri" "pub/media/$uri"
    fi
done
