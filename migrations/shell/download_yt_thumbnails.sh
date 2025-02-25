psql $DATABASE_URL \
    -c "SELECT id, substring(body from 'vi\/([a-zA-z0-9\-_]+)\/') AS video_id, \
    substring(body from 'vi\/[a-zA-z0-9\-_]+/(\w+)\.jpg') AS size \
    FROM posts WHERE body LIKE '%<img src=\"https://img.youtube.com/vi%' \
    AND status = 'approved';" \
    --field-separator=' ' \
    --no-align \
    --quiet \
    --tuples-only \
| while read id video_id size; do
    echo "Processing post $id"
    if [ ! -f "pub/youtube/$video_id/$size.jpg" ]; then
        echo "Downloading thumbnail for $video_id in $size"
        mkdir -p "pub/youtube/$video_id"
        curl -s "https://img.youtube.com/vi/$video_id/$size.jpg" \
            -o "pub/youtube/$video_id/$size.jpg"
        psql $DATABASE_URL \
            -c "UPDATE posts SET body = \
            replace(body, '<img src=\"https://img.youtube.com/vi/$video_id/$size.jpg', \
            '<img src=\"/youtube/$video_id/$size.jpg') WHERE id = $id;"
    fi
done
