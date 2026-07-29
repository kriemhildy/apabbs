#!/bin/bash
# This script cleans up old versions of Chrome installed by Puppeteer

CHROME_DIR="chrome"            # default puppeteer chrome directory
KEEP=3                         # keep the 3 newest versions

cd "$CHROME_DIR" || exit 1

# Sort Chrome directory alphabetically (descending) and remove old versions.
idx=0
ls -1d -- */ | sort -r | while IFS= read -r dir; do
  idx=$((idx + 1))
  if [ "$idx" -le "$KEEP" ]; then
    continue
  fi

  echo "Removing old Chrome version: ${dir%/}"
  rm -r -- "${dir%/}"
done
