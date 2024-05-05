set -xe
if ! [ "$DEV" == 1 ]; then
    git pull
    nice ../.cargo/bin/rustup upgrade
    nice ../.cargo/bin/cargo build --release
else
    cargo test
    git push
    ssh $SSH_APP "cd schiz && script/deploy.sh"
    ssh $SSH_SUDO "sudo systemctl stop schiz"
    ssh $SSH_APP "cd schiz && ../.cargo/bin/sqlx migrate run"
    ssh $SSH_SUDO "sudo systemctl start schiz"
fi
