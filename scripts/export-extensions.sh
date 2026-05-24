#!/usr/bin/env bash
# Export all installed VS Code extensions as .vsix files for offline installation.
# Reads the VS Code extensions catalog to get exact versions and target platforms.
#
# Usage:
#   bash export-extensions.sh                  # saves to ./vscode-extensions-export/
#   bash export-extensions.sh ./my-backup      # saves to a custom directory
#
# Output:
#   <dir>/vsix/                        - one .vsix file per extension
#   <dir>/install.sh                   - offline vsix installer (no internet needed)
#   <dir>/install-from-marketplace.sh  - online installer (resets install_source to gallery)
set -euo pipefail

CODE=${CODE_BINARY:-code}
OUTPUT_DIR=${1:-./vscode-extensions-export}
VSIX_DIR="$OUTPUT_DIR/vsix"
INSTALL_SCRIPT="$OUTPUT_DIR/install.sh"
MARKETPLACE_SCRIPT="$OUTPUT_DIR/install-from-marketplace.sh"
CATALOG="$HOME/.vscode/extensions/extensions.json"

# ── Preflight ──────────────────────────────────────────────────────────────────

if ! command -v "$CODE" &>/dev/null; then
    echo "Error: '$CODE' not found. Set CODE_BINARY if using a non-standard install." >&2
    exit 1
fi
if ! command -v curl &>/dev/null; then
    echo "Error: curl is required." >&2
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is required." >&2
    exit 1
fi
if [[ ! -f "$CATALOG" ]]; then
    echo "Error: extensions catalog not found at $CATALOG" >&2
    exit 1
fi

mkdir -p "$VSIX_DIR"

# ── Parse catalog with python ──────────────────────────────────────────────────
# Outputs lines: publisher.name TAB version TAB targetPlatform
# targetPlatform is empty string for universal extensions

catalog_data=$(python3 - "$CATALOG" <<'PYEOF'
import json, re, sys

VALID_EXTENSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*\.[A-Za-z0-9][A-Za-z0-9_-]*$")
VALID_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
VALID_PLATFORMS = {
    "linux-x64", "linux-arm64", "linux-armhf", "darwin-arm64", "darwin-x64",
    "win32-x64", "win32-arm64", "win32-ia32", "alpine-arm64", "alpine-x64",
}

with open(sys.argv[1]) as f:
    catalog = json.load(f)

seen = set()
for entry in catalog:
    ident = entry.get("identifier", {})
    ext_id = ident.get("id", "").lower()
    if not ext_id:
        continue
    if not VALID_EXTENSION_ID.fullmatch(ext_id):
        print(f"WARNING: skipping invalid extension id {ext_id!r}", file=sys.stderr)
        continue
    if ext_id in seen:
        continue
    seen.add(ext_id)

    meta = entry.get("metadata", {})
    version = meta.get("version", "")
    if not version:
        # Fall back to parsing version from relativeLocation
        loc = entry.get("relativeLocation", "")
        # loc format: publisher.name-version or publisher.name-version-platform
        parts = loc.rsplit("-", 1)
        # Try to find the version component
        for p in reversed(loc.split("-")):
            if p and p[0].isdigit():
                version = p
                break

    if version and not VALID_VERSION.fullmatch(version):
        print(f"WARNING: skipping invalid version {version!r} for {ext_id}", file=sys.stderr)
        continue

    platform = meta.get("targetPlatform", "")
    if platform in ("undefined", None):
        platform = ""
    elif platform not in VALID_PLATFORMS:
        print(f"WARNING: skipping unknown platform {platform!r} for {ext_id}", file=sys.stderr)
        platform = ""

    if ext_id and version:
        print(f"{ext_id}\t{version}\t{platform}")
PYEOF
)

total=$(echo "$catalog_data" | wc -l)
echo "Found $total extensions in catalog."

echo

# ── Download each extension ────────────────────────────────────────────────────
# For platform-specific extensions, also download the universal build so this
# archive can be used on any target platform (linux-x64, win32-x64, darwin-arm64, etc.)

VALID_PLATFORMS="linux-x64 linux-arm64 linux-armhf darwin-arm64 darwin-x64 win32-x64 win32-arm64 win32-ia32 alpine-arm64 alpine-x64"

failed=()
count=0
ext_ids=()  # collected for marketplace install script

_valid_platform() {
    local p="$1"
    for vp in $VALID_PLATFORMS; do
        [[ "$p" == "$vp" ]] && return 0
    done
    return 1
}

_valid_extension_id() {
    [[ "$1" =~ ^[[:alnum:]][[:alnum:]_-]*\.[[:alnum:]][[:alnum:]_-]*$ ]]
}

_valid_extension_version() {
    [[ "$1" =~ ^[[:alnum:]][[:alnum:]._+-]*$ ]]
}

_download() {
    local filename="$1" url="$2"
    local dest="$VSIX_DIR/$filename"
    local tmp="${dest}.tmp"

    if [[ -f "$dest" ]]; then
        if python3 -c "
import sys
with open(sys.argv[1],'rb') as f: sig=f.read(4)
sys.exit(0 if sig==b'PK\x03\x04' else 1)
" "$dest" 2>/dev/null; then
            printf "  %-60s already downloaded\n" "$filename"
            return 0
        else
            rm -f "$dest"
        fi
    fi

    printf "  %-60s " "$filename"
    local http_code
    http_code=$(curl -fsSL --compressed "$url" -o "$tmp" -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ -f "$tmp" ]] && python3 -c "
import sys
with open(sys.argv[1],'rb') as f: sig=f.read(4)
sys.exit(0 if sig==b'PK\x03\x04' else 1)
" "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$dest"
        local size
        size=$(du -sh "$dest" 2>/dev/null | cut -f1)
        echo "ok ($size)"
        return 0
    else
        rm -f "$tmp"
        echo "FAILED (http $http_code)"
        return 1
    fi
}

while IFS=$'\t' read -r ext_id version platform; do
    if ! _valid_extension_id "$ext_id"; then
        echo "  WARNING: skipping invalid extension id '$ext_id'" >&2
        continue
    fi
    if ! _valid_extension_version "$version"; then
        echo "  WARNING: skipping invalid version '$version' for $ext_id" >&2
        continue
    fi

    count=$((count + 1))
    ext_ids+=("$ext_id")
    publisher="${ext_id%%.*}"
    name="${ext_id#*.}"
    base_url="https://marketplace.visualstudio.com/_apis/public/gallery/publishers/${publisher}/vsextensions/${name}/${version}/vspackage"

    printf "[%3d/%d] %s v%s\n" "$count" "$total" "$ext_id" "$version"

    # Always download the universal build
    _download "${ext_id}-${version}.vsix" "$base_url" \
        || failed+=("${ext_id}@${version} (universal)")

    # Also download the platform-specific build if this extension has one
    if [[ -n "$platform" ]]; then
        if _valid_platform "$platform"; then
            _download "${ext_id}-${version}-${platform}.vsix" "${base_url}?targetPlatform=${platform}" \
                || failed+=("${ext_id}@${version} ($platform)")
        else
            echo "  WARNING: skipping unknown platform '$platform' for $ext_id"
        fi
    fi

done <<< "$catalog_data"

# ── Write install script ────────────────────────────────────────────────────────
# The generated install.sh is fully self-contained: it detects the target
# platform at runtime and picks the best .vsix for each extension
# (platform-specific preferred, universal as fallback).

cat > "$INSTALL_SCRIPT" <<'INSTALL_EOF'
#!/usr/bin/env bash
# Install VS Code extensions from .vsix files (offline).
# Copy this file AND the vsix/ folder to the target machine, then run:
#   bash install.sh
set -euo pipefail

CODE=${CODE_BINARY:-code}
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vsix"

if ! command -v "$CODE" &>/dev/null; then
    echo "Error: VS Code CLI '$CODE' not found." >&2
    echo "Set CODE_BINARY if using a non-standard install path." >&2
    exit 1
fi

_detect_platform() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)
            case "$arch" in
                x86_64)  echo "linux-x64" ;;
                aarch64) echo "linux-arm64" ;;
                armv7l)  echo "linux-armhf" ;;
                *)        echo "linux-x64" ;;
            esac ;;
        Darwin)
            case "$arch" in
                arm64) echo "darwin-arm64" ;;
                *)     echo "darwin-x64" ;;
            esac ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "win32-x64" ;;
        *)
            echo "linux-x64" ;;
    esac
}

PLATFORM=$(_detect_platform)
echo "Detected platform: $PLATFORM"
echo

# All known platform suffixes (longest first so matching is unambiguous)
KNOWN_PLATFORMS="linux-x64 linux-arm64 linux-armhf darwin-arm64 darwin-x64 win32-x64 win32-arm64 win32-ia32 alpine-arm64 alpine-x64"

# Build a map: base_id-version -> best filename
# Platform-specific match for PLATFORM beats universal; universal beats other platforms.
declare -A best_file
declare -A best_priority  # 2=exact platform, 1=universal, 0=other platform

for f in "$DIR"/*.vsix; do
    [[ -f "$f" ]] || continue
    filename=$(basename "$f" .vsix)

    file_platform=""
    base="$filename"
    for p in $KNOWN_PLATFORMS; do
        if [[ "$filename" == *"-${p}" ]]; then
            file_platform="$p"
            base="${filename%-${p}}"
            break
        fi
    done

    if [[ "$file_platform" == "$PLATFORM" ]]; then
        priority=2
    elif [[ -z "$file_platform" ]]; then
        priority=1
    else
        priority=0
    fi

    current_priority="${best_priority[$base]:-99}"
    # 99 = not set; lower stored value means we haven't assigned yet or this is better
    if [[ "$current_priority" -eq 99 ]] || [[ "$priority" -gt "$current_priority" ]]; then
        best_file["$base"]="$(basename "$f")"
        best_priority["$base"]="$priority"
    fi
done

TOTAL=${#best_file[@]}
echo "Installing $TOTAL extensions for platform: $PLATFORM"
echo

failed=()
count=0

for base in "${!best_file[@]}"; do
    count=$((count + 1))
    filename="${best_file[$base]}"
    printf "  [%d/%d] %s ... " "$count" "$TOTAL" "$filename"
    if "$CODE" --install-extension "$DIR/$filename" --force &>/dev/null; then
        echo "ok"
    else
        echo "FAILED"
        failed+=("$filename")
    fi
done

echo
if [ ${#failed[@]} -eq 0 ]; then
    echo "Done. Restart VS Code to activate all extensions."
else
    echo "${#failed[@]} extension(s) failed to install:"
    for f in "${failed[@]}"; do echo "  - $f"; done
    exit 1
fi
INSTALL_EOF

chmod +x "$INSTALL_SCRIPT"

# ── Write install-from-marketplace.sh ──────────────────────────────────────────
# Installs each extension directly from the VS Code Marketplace by ID.
# This resets install_source to 'gallery' and re-enables auto-updates.
# Requires internet access on the target machine.

{
cat <<'MKTPLACE_HEADER'
#!/usr/bin/env bash
# Install VS Code extensions from the Marketplace (online).
# Uninstalls each extension first so VS Code records install_source='gallery',
# which re-enables automatic updates.
#
# IMPORTANT: Close VS Code before running this script.
#   bash install-from-marketplace.sh
set -euo pipefail

CODE=${CODE_BINARY:-code}

if ! command -v "$CODE" &>/dev/null; then
    echo "Error: VS Code CLI '$CODE' not found." >&2
    echo "Set CODE_BINARY if using a non-standard install path." >&2
    exit 1
fi

echo "NOTE: Close VS Code before running this script."
echo "Extensions will be uninstalled then reinstalled from the Marketplace."
echo "Your settings and configuration will not be affected."
echo

MKTPLACE_HEADER

echo "EXTENSIONS=("
for ext_id in "${ext_ids[@]}"; do
    printf "  %q\n" "$ext_id"
done
echo ")"
echo ""

cat <<'MKTPLACE_FOOTER'
TOTAL=${#EXTENSIONS[@]}
echo "Reinstalling $TOTAL extensions from Marketplace..."
echo

failed=()
count=0

for ext in "${EXTENSIONS[@]}"; do
    count=$((count + 1))
    printf "  [%d/%d] %s ... " "$count" "$TOTAL" "$ext"
    "$CODE" --uninstall-extension "$ext" &>/dev/null || true
    if "$CODE" --install-extension "$ext" &>/dev/null; then
        echo "ok"
    else
        echo "FAILED"
        failed+=("$ext")
    fi
done

echo
if [ ${#failed[@]} -eq 0 ]; then
    echo "Done. Restart VS Code to activate all extensions."
else
    echo "${#failed[@]} extension(s) failed to install:"
    for f in "${failed[@]}"; do echo "  - $f"; done
    exit 1
fi
MKTPLACE_FOOTER
} > "$MARKETPLACE_SCRIPT"

chmod +x "$MARKETPLACE_SCRIPT"

# ── Summary ────────────────────────────────────────────────────────────────────

downloaded_count=$(find "$VSIX_DIR" -name "*.vsix" | wc -l)

echo
echo "─────────────────────────────────────────────────"
printf "  Downloaded : %d files (%d extensions)\n" "$downloaded_count" "$count"
if [ ${#failed[@]} -gt 0 ]; then
    printf "  Failed     : %d\n" "${#failed[@]}"
    for f in "${failed[@]}"; do echo "    - $f"; done
fi
total_size=$(du -sh "$VSIX_DIR" 2>/dev/null | cut -f1)
echo "  Total size : $total_size"
echo "  Output     : $OUTPUT_DIR"
echo "  Offline    : bash $INSTALL_SCRIPT"
echo "  Marketplace: bash $MARKETPLACE_SCRIPT"
echo "─────────────────────────────────────────────────"

[[ ${#failed[@]} -eq 0 ]]
