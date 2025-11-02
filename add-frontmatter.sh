#!/bin/bash

# Script to add Jekyll front matter to all markdown files in _features/user-authentication

find _features/user-authentication -name "*.md" -type f | while read file; do
    # Skip if file already has front matter
    if head -n 1 "$file" | grep -q "^---$"; then
        echo "Skipping $file (already has front matter)"
        continue
    fi

    # Get filename without path and extension
    basename=$(basename "$file" .md)

    # Create title from filename (replace hyphens/underscores with spaces, capitalize)
    title=$(echo "$basename" | sed 's/[-_]/ /g' | sed 's/\b\(.\)/\u\1/g')

    # Add front matter
    echo "Adding front matter to: $file"
    temp_file=$(mktemp)

    cat > "$temp_file" << EOF
---
layout: default
title: $title
nav_exclude: true
---

EOF

    cat "$file" >> "$temp_file"
    mv "$temp_file" "$file"
done

echo "Done! Front matter added to all markdown files."
