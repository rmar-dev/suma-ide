#!/bin/bash

# Script to fix Jekyll front matter in all markdown files

find _features/user-authentication -name "*.md" -type f | while read file; do
    # Skip index files and main file
    if [[ "$file" == *"/index.md" ]] || [[ "$file" == "_features/user-authentication.md" ]]; then
        echo "Skipping: $file"
        continue
    fi

    # Check if file has front matter
    if head -n 1 "$file" | grep -q "^---$"; then
        echo "Fixing front matter in: $file"

        # Get filename without path and extension
        basename=$(basename "$file" .md)

        # Create title from filename
        title=$(echo "$basename" | sed 's/[-_]/ /g' | sed 's/\b\(.\)/\u\1/g')

        # Extract content after front matter (skip until second ---)
        content=$(awk '/^---$/{if(++count==2){flag=1;next}}flag' "$file")

        # Create new file with updated front matter
        temp_file=$(mktemp)
        cat > "$temp_file" << EOF
---
layout: default
title: $title
nav_exclude: true
---

$content
EOF
        mv "$temp_file" "$file"
    fi
done

echo "Done! Front matter fixed in all markdown files."
