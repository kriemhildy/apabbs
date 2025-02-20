echo "Moving pub/media to pub/m"
mv pub/media pub/m
psql $DATABASE_URL \
    -c "SELECT uuid, pub_id FROM posts WHERE media_file_name IS NOT NULL" \
    --field-separator=' ' \
    --no-align \
    --quiet \
    --tuples-only \
| while read uuid pub_id; do
    if [ -d "pub/m/$uuid" ]; then
        echo "Moving media from $uuid to $pub_id"
        mv "pub/media/$uuid" "pub/media/$pub_id"
    fi
done
