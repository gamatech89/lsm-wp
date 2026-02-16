#!/bin/bash
#
# Build and release the Landeseiten Maintenance WordPress plugin.
#
# Usage:
#   ./build-release.sh <version>
#   ./build-release.sh 2.0.0
#
# This script:
#   1. Updates the version in the main plugin file
#   2. Creates a distributable .zip
#   3. Commits, tags, and pushes to GitHub
#   4. Creates a GitHub release with the .zip attached
#
# Requirements:
#   - GitHub CLI (gh) installed and authenticated
#   - git configured with push access to the repo
#

set -euo pipefail

VERSION="${1:-}"
PLUGIN_SLUG="landeseiten-maintenance"
PLUGIN_DIR="$PLUGIN_SLUG"
MAIN_FILE="$PLUGIN_DIR/landeseiten-maintenance.php"
ZIP_FILE="${PLUGIN_SLUG}.zip"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ -z "$VERSION" ]]; then
    echo -e "${RED}Error: Please provide a version number.${NC}"
    echo "Usage: ./build-release.sh <version>"
    echo "Example: ./build-release.sh 2.0.1"
    exit 1
fi

# Validate semver format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: Version must be in semver format (e.g., 2.0.1)${NC}"
    exit 1
fi

echo -e "${YELLOW}🔧 Building Landeseiten Maintenance v${VERSION}${NC}"

# 1. Update version in plugin header and constant
echo -e "${GREEN}→ Updating version to ${VERSION}...${NC}"
sed -i '' "s/^ \* Version: .*/\ * Version: ${VERSION}/" "$MAIN_FILE"
sed -i '' "s/define('LSM_VERSION', '.*');/define('LSM_VERSION', '${VERSION}');/" "$MAIN_FILE"

# Verify version was updated
HEADER_VERSION=$(grep "Version:" "$MAIN_FILE" | head -1 | sed 's/.*Version: //' | tr -d '[:space:]')
CONST_VERSION=$(grep "LSM_VERSION" "$MAIN_FILE" | head -1 | grep -oP "(?<=')[^']+(?=')" | tail -1)

echo "  Header version: $HEADER_VERSION"
echo "  Constant version: $CONST_VERSION"

# 2. Create zip archive
echo -e "${GREEN}→ Creating ${ZIP_FILE}...${NC}"
rm -f "$ZIP_FILE"
zip -r "$ZIP_FILE" "$PLUGIN_DIR/" \
    -x "${PLUGIN_DIR}/.DS_Store" \
    -x "${PLUGIN_DIR}/**/.DS_Store" \
    -x "${PLUGIN_DIR}/.git/*" \
    -x "${PLUGIN_DIR}/node_modules/*" \
    -x "${PLUGIN_DIR}/.env"

ZIP_SIZE=$(du -h "$ZIP_FILE" | cut -f1)
echo "  Archive size: $ZIP_SIZE"

# 3. Git commit, tag, push
echo -e "${GREEN}→ Committing and tagging v${VERSION}...${NC}"
git add -A
git commit -m "Release v${VERSION}" || echo "  (nothing to commit)"
git tag -a "v${VERSION}" -m "Release v${VERSION}" 2>/dev/null || {
    echo -e "${RED}Tag v${VERSION} already exists. Delete it first if re-releasing.${NC}"
    exit 1
}
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git push origin "$BRANCH" --tags

# 4. Create GitHub release with zip
echo -e "${GREEN}→ Creating GitHub release...${NC}"
gh release create "v${VERSION}" "$ZIP_FILE" \
    --title "v${VERSION}" \
    --notes "Landeseiten Maintenance Plugin v${VERSION}" \
    --latest

echo ""
echo -e "${GREEN}✅ Released v${VERSION} successfully!${NC}"
echo -e "   GitHub: https://github.com/gamatech89/lsm-wp/releases/tag/v${VERSION}"
echo ""
echo -e "${YELLOW}📋 Next steps:${NC}"
echo "   Existing sites with v2.0.0+ will get the update notification automatically."
echo "   For new installs, download the zip from the GitHub release page."
