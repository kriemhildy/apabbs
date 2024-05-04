set -x
nice pg_dump $DATABASE_URL > schiz.sql
nice gzip --force schiz.sql
