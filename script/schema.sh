set -x
pg_dump --schema-only $PG_URL > db/schema.sql
