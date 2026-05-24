#!/usr/bin/env bash
# Update all installed VS Code extensions to their latest Marketplace versions.
set -euo pipefail

CODE=${CODE_BINARY:-code}

if ! command -v "$CODE" &>/dev/null; then
    echo "Error: '$CODE' not found. Set CODE_BINARY if using a non-standard install." >&2
    exit 1
fi

extensions=$("$CODE" --list-extensions)
total=$(echo "$extensions" | wc -l)
count=0
failed=()

echo "Updating $total extensions..."
echo

while IFS= read -r ext; do
    count=$((count + 1))
    if [[ ! "$ext" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "WARNING: skipping invalid extension ID: $ext" >&2
        continue
    fi
    printf "[%d/%d] %s ... " "$count" "$total" "$ext"
    if "$CODE" --install-extension "$ext" --force &>/dev/null; then
        echo "ok"
    else
        echo "FAILED"
        failed+=("$ext")
    fi
done <<< "$extensions"

echo
if [ ${#failed[@]} -eq 0 ]; then
    echo "All $total extensions updated successfully."
else
    echo "${#failed[@]} extension(s) failed to update:"
    for f in "${failed[@]}"; do
        echo "  - $f"
    done
    exit 1
fi

echo
echo "Restart VS Code to apply the updates."
echo "The old versions remain active until VS Code relaunches."
