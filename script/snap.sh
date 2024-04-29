set -x
nice pg_dump $DATABASE_URL > db/schiz.sql
nice gzip --force db/schiz.sql
