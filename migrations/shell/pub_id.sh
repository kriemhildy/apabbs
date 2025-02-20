psql $DATABASE_URL \
    -c "SELECT uuid, pub_id FROM posts WHERE media_file_name IS NOT NULL" \
    --field-separator=' ' \
    --no-align \
    --quiet \
    --tuples-only \
| while read uuid pub_id; do
  echo "Moving media from $uuid to $pub_id"
  mv "pub/media/$uuid" "pub/media/$pub_id"
done
