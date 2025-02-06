psql $DATABASE_URL \
    --command="SELECT uuid, media_file_name FROM posts WHERE thumbnail_file_name IS NULL \
        AND status = 'approved' \
        AND media_file_name SIMILAR TO '%.(jpg|jpeg|jfif|pjpeg|pjp|png|avif|bmp|tiff|tif|webp)';" \
    --quiet \
    --no-align \
    --tuples-only \
    --field-separator ' ' \
| while read -r uuid media_file_name; do
    echo "Generating thumbnail for pub/media/$uuid/$media_file_name"
    vipsthumbnail \
        --size "1400x1600>" \
        --eprofile=srgb \
        --output "tn_%s.jpg[optimize_coding,strip]" \
        "pub/media/$uuid/$media_file_name"
    thumbnail_file_name="tn_$(\
        echo $media_file_name\
        | sed -E 's/\.(jpg|jpeg|jfif|pjpeg|pjp|png|avif|bmp|tiff|tif|webp)$/.jpg/i')"
    echo "Thumbnail generated: $thumbnail_file_name"
    psql $DATABASE_URL \
       --command="UPDATE posts SET thumbnail_file_name = '$thumbnail_file_name' WHERE uuid = '$uuid';"
done
