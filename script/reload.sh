set -x
if ! [ "$DEV" == 1 ]; then
    echo "do not run reload on production"
    exit 1
fi
ssh $SSH_APP_USER "cd schiz && script/snap.sh"
scp $SSH_APP_USER:schiz/schiz.sql.gz .
ssh $SSH_APP_USER "rm schiz/schiz.sql.gz"
gunzip --force schiz.sql.gz
dropdb schiz
createdb schiz -O schiz
psql $DATABASE_URL < schiz.sql
rm schiz.sql
rsync -av --del $SSH_APP_USER:schiz/uploads .
rsync -av --del $SSH_APP_USER:schiz/pub/media pub
