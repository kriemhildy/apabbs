#!/bin/bash
# This script syncs the database and uploaded media files from the production server to your local development environment
# It enables testing with real data while maintaining a separation between environments

# Print each command before executing (useful for debugging)
set -x

# Safety check: Ensure we're not running this script in production
# This prevents accidental data corruption on the production server
if ! [ "$DEV" == 1 ]; then
    echo "do not run sync in production"
    exit 1
fi

# Step 1: Create a database snapshot on the production server
ssh $SSH_APP_USER "cd $SSH_APP_PATH && script/snap.sh"

# Step 2: Download the compressed database backup from the production server
scp $SSH_APP_USER:$SSH_APP_PATH/apabbs.sql.gz .

# Step 3: Clean up the backup file on the production server to save space
ssh $SSH_APP_USER "rm $SSH_APP_PATH/apabbs.sql.gz"

# Step 4: Decompress the downloaded database backup
gunzip --force apabbs.sql.gz

# Step 5: Reset the local database
# Drop the existing database to ensure a clean slate
sqlx database drop -y
# Create a new empty database
sqlx database create

# Step 6: Import the production data into the local database
psql $DATABASE_URL < apabbs.sql

# Step 7: Clean up the local SQL file after import
rm apabbs.sql

# Step 8: Sync media files from production to local development
# Transfer user-uploaded content (encrypted files)
rsync -av --del $SSH_APP_USER:$SSH_APP_PATH/uploads .
# Transfer public media files (published content)
rsync -av --del $SSH_APP_USER:$SSH_APP_PATH/pub/media pub
# Transfer YouTube thumbnail cache
rsync -av --del $SSH_APP_USER:$SSH_APP_PATH/pub/youtube pub

# At this point, the local development environment has a complete copy of:
# - The production database structure and content
# - All uploaded and published media files
# - YouTube thumbnails and cached content
