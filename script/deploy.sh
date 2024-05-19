set -xe
if ! [ "$DEV" == 1 ]; then
    git pull
    nice ../.cargo/bin/rustup upgrade
    nice ../.cargo/bin/cargo build --release
else
    cargo test
    git push
    ssh $APP_SSH_ACCOUNT "cd schiz && script/deploy.sh"
    ssh $SUDO_SSH_ACCOUNT "sudo systemctl stop apabbs"
    ssh $APP_SSH_ACCOUNT "cd schiz && ../.cargo/bin/sqlx migrate run"
    ssh $SUDO_SSH_ACCOUNT "sudo systemctl start apabbs"
fi
