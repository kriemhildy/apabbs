#!/bin/bash
# This script deploys the application to the server.

# Exit immediately if a command fails and print each command before executing
set -xe

# Check if we're in development mode or running on the server
if ! [ "$DEV" == 1 ]; then
    # Server-side deployment steps
    # ----------------------------

    # Load Cargo environment variables
    source $HOME/.cargo/env

    # Update code repository with latest changes
    git pull

    # Update Rust to the latest version
    nice rustup update

    # Compile the application in release mode
    nice cargo build --release

    # Generate documentation without dependencies
    nice cargo doc --no-deps --release
else
    # Local development deployment steps
    # ----------------------------------

    # Safety check: Ensure we're on the master branch
    if [ `git branch --show-current` != "master" ]; then
        echo "Not on master branch"
        exit 1
    fi

    # Safety check: Ensure there are no uncommitted changes
    # Checks for staged changes, unstaged changes, and untracked files
    if ! git diff --quiet || \
       ! git diff --cached --quiet || \
       [[ $(git ls-files --other --exclude-standard) ]]; then
        echo "Uncommitted changes"
        exit 1
    fi

    # Update Rust to the latest version
    nice rustup update

    # Run all tests to verify the code works correctly
    nice cargo test

    # Push local changes to the remote repository
    git push

    # Remote commands: Execute the deployment script on the server
    ssh $SSH_APP_USER "cd $SSH_APP_PATH && script/deploy.sh"

    # Stop the application service (requires sudo)
    ssh $SSH_SUDO_USER "sudo systemctl stop $SSH_SERVICE"

    # Run migrations
    ssh $SSH_APP_USER "cd $SSH_APP_PATH && ~/.cargo/bin/sqlx migrate run && target/release/migrate"

    # Start the application service (requires sudo)
    ssh $SSH_SUDO_USER "sudo systemctl start $SSH_SERVICE"
fi
