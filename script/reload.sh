set -x
if ! [ "$DEV" == 1 ]; then
    echo "do not run reload on production"
    exit 1
fi
ssh $SSH_APP_USER "cd $SSH_APP_PATH && script/snap.sh"
scp $SSH_APP_USER:$SSH_APP_PATH/apabbs.sql.gz .
ssh $SSH_APP_USER "rm $SSH_APP_PATH/apabbs.sql.gz"
gunzip --force apabbs.sql.gz
sqlx database drop
sqlx database create
psql $DATABASE_URL < apabbs.sql
rm apabbs.sql
rsync -av --del $SSH_APP_USER:$SSH_APP_PATH/uploads .
rsync -av --del $SSH_APP_USER:$SSH_APP_PATH/pub/media pub
