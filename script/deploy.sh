set -xe
if ! [ "$DEV" == 1 ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    git pull
    nice rustup upgrade
    nice cargo build --release
else
    git diff --quiet
    git diff --cached --quiet
    cargo test
    git push
    ssh $SSH_APP_USER "cd $SSH_APP_PATH && script/deploy.sh"
    ssh $SSH_SUDO_USER "sudo systemctl stop $SSH_SERVICE"
    ssh $SSH_APP_USER "cd $SSH_APP_PATH && ~/.cargo/bin/sqlx migrate run"
    ssh $SSH_SUDO_USER "sudo systemctl start $SSH_SERVICE"
    git push github
fi
