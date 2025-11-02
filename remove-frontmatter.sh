#!/bin/bash

# Script to remove front matter from nested documentation files
# This prevents Jekyll from trying to process them as pages

find _features/user-authentication -name "*.md" -type f | while read file; do
    # Skip index files and main file
    if [[ "$file" == *"/index.md" ]] || [[ "$file" == "_features/user-authentication.md" ]]; then
        echo "Skipping: $file"
        continue
    fi

    # Check if file has front matter
    if head -n 1 "$file" | grep -q "^---$"; then
        echo "Removing front matter from: $file"

        # Extract content after front matter (skip until second ---)
        content=$(awk '/^---$/{if(++count==2){flag=1;next}}flag' "$file")

        # Write content without front matter
        echo "$content" > "$file"
    fi
done

echo "Done! Front matter removed from nested files."
