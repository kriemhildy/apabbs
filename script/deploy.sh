set -xe
if ! [ "$DEV" == 1 ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    git pull
    nice rustup upgrade
    nice cargo build --release
else
    cargo test
    git push
    ssh $APP_SSH_ACCOUNT "cd schiz && script/deploy.sh"
    ssh $SUDO_SSH_ACCOUNT "sudo systemctl stop apabbs"
    ssh $APP_SSH_ACCOUNT "cd schiz && ~/.cargo/bin/sqlx migrate run"
    ssh $SUDO_SSH_ACCOUNT "sudo systemctl start apabbs"
fi
