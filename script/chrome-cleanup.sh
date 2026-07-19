#!/bin/bash
CHROME_DIR="chrome"            # default puppeteer chrome directory
KEEP=3                         # keep the 3 newest versions

cd "$CHROME_DIR" || exit 1

# Find version directories (they look like linux-xxx.y.z.w/)
echo "=== Chrome versions before cleanup ==="
ls -1d linux-* 2>/dev/null || echo "No versions found"

# Keep the newest KEEP versions, delete the rest
find . -maxdepth 1 -name 'linux-*' -type d -print0 | \
  sort -z -V -r | \
  tail -z -n +$((KEEP+1)) | \
  xargs -0 rm -rf -- 2>/dev/null || true

echo "=== After cleanup (keeping $KEEP newest) ==="
ls -1d linux-* 2>/dev/null || echo "No versions left"
