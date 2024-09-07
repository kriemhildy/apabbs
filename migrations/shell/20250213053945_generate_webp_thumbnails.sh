psql $DATABASE_URL \
    --command="SELECT pub_id, media_file_name FROM posts \
        WHERE status = 'approved' AND media_category = 'image';" \
    --quiet \
    --no-align \
    --tuples-only \
    --field-separator ' ' \
| while read -r pub_id media_file_name; do
    echo "Generating webp thumbnail for pub/media/$pub_id/$media_file_name"
    # extension=$(echo "${media_file_name##*.}" | tr '[:upper:]' '[:lower:]')
    extension=$(echo "${media_file_name##*.}" | tr '[:upper:]' '[:lower:]')
    echo "Extension: $extension"
    vips_input_file_path="pub/media/$pub_id/$media_file_name"
    if [[ $extension == "webp" || $extension == "gif" ]]; then
        vips_input_file_path="$vips_input_file_path[n=-1]"
    fi
    echo "vips input file path: $vips_input_file_path"
    vipsthumbnail \
        --size "1200x1600>" \
        --output "tn_%s.webp" \
        "$vips_input_file_path"
    file_name_without_extension="${media_file_name%.*}"
    echo "Filename without extension: $file_name_without_extension"
    thumbnail_file_name="tn_$file_name_without_extension.webp"
    echo "Thumbnail generated: $thumbnail_file_name"
    psql $DATABASE_URL \
       --command="UPDATE posts SET thumbnail_file_name = '$thumbnail_file_name' WHERE pub_id = '$pub_id';"
    old_jpg_thumbnail="pub/media/$pub_id/tn_$file_name_without_extension.jpg"
    if [ -f "$old_jpg_thumbnail" ]; then
        echo "delete old jpg thumbnail $old_jpg_thumbnail"
        rm "$old_jpg_thumbnail"
    fi
done
