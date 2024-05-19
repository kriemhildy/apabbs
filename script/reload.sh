set -x
if ! [ "$DEV" == 1 ]; then
    echo "do not run reload on production"
    exit 1
fi
ssh $APP_SSH_ACCOUNT "cd schiz && script/snap.sh"
scp $APP_SSH_ACCOUNT:schiz/schiz.sql.gz .
ssh $APP_SSH_ACCOUNT "rm schiz/schiz.sql.gz"
gunzip --force schiz.sql.gz
dropdb schiz
createdb schiz -O schiz
psql $DATABASE_URL < schiz.sql
rm schiz.sql
