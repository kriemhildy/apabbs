set -xe
if ! [ "$DEV" == 1 ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    git pull
    nice rustup upgrade
    nice cargo build --release
else
    cargo test
    git push
    ssh $SSH_APP_USER "cd schiz && script/deploy.sh"
    ssh $SSH_SUDO_USER "sudo systemctl stop apabbs"
    ssh $SSH_APP_USER "cd schiz && ~/.cargo/bin/sqlx migrate run"
    ssh $SSH_SUDO_USER "sudo systemctl start apabbs"
fi
