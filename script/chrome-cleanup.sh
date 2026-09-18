#!/bin/bash
# This script cleans up old versions of Chrome installed by Puppeteer

CHROME_DIR="chrome"            # default puppeteer chrome directory
KEEP=1                         # only keep the newest version

cd "$CHROME_DIR" || exit 1

# Sort Chrome directories by modification time (newest first) and remove old ones.
ls -1t | tail -n +$((KEEP + 1)) | while IFS= read -r dir; do
  [ -n "$dir" ] || continue
  echo "Removing old Chrome version: $dir"
  rm -r -- "$dir"
done
