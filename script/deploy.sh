set -xe
if ! [ $DEV == 1 ]; then
    git pull
    nice ../.cargo/bin/cargo build --release
    nice ../.cargo/bin/sqlx migrate run
else
    cargo test --bins
    git push
    ssh $SSH_APP "cd schiz && script/deploy.sh"
    ssh $SSH_SUDO "sudo systemctl restart schiz"
fi
