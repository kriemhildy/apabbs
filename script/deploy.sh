set -xe
if ! [ "$DEV" == 1 ]; then
    source $HOME/.cargo/env
    git pull
    nice rustup update
    nice cargo build --release
else
    if [ `git branch --show-current` != "main" ]; then
        echo "Not on main branch"
        exit 1
    fi
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "Uncommitted changes"
        exit 1
    fi
    nice rustup update
    nice cargo test
    git push
    ssh $SSH_APP_USER "cd $SSH_APP_PATH && script/deploy.sh"
    ssh $SSH_SUDO_USER "sudo systemctl stop $SSH_SERVICE"
    ssh $SSH_APP_USER "cd $SSH_APP_PATH && ~/.cargo/bin/sqlx migrate run"
    ssh $SSH_SUDO_USER "sudo systemctl start $SSH_SERVICE"
fi
