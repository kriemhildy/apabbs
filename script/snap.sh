set -x
nice pg_dump $DATABASE_URL > apabbs.sql
nice gzip --force apabbs.sql
