set -x
if ! [ "$DEV" == 1 ]; then
    echo "do not run reload on production"
    exit 1
fi
ssh $SSH_APP "cd schiz && script/snap.sh"
scp $SSH_APP:schiz/db/schiz.sql.gz db
gunzip --force db/schiz.sql.gz
dropdb schiz
createdb schiz -O schiz
psql $DATABASE_URL < db/schiz.sql
