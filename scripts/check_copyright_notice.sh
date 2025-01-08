#!/bin/sh
set -e

check_copyright_notices() {
    exitcode=0
    for file in "$@"; do
        if head -n1 "$file" | grep -q "// Copyright .* Ulvetanna Inc."; then
            echo "$file: ERROR - Copyright notice is using Ulvetanna instead of Irreducible"
            exitcode=1
        elif ! head -n1 "$file" | grep -q "// Copyright "; then
            echo "$file: ERROR - Copyright notice missing on first line"
            exitcode=1
        fi
    done
    exit $exitcode
}

# Check if directories are passed as arguments
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <directory1> [directory2 ...]"
    exit 1
fi

file_list=""

# Iterate over arguments (directories) and collect .rs files
for dir in "$@"; do
    if [ -d "$dir" ]; then
        # Collect .rs files in the directory
        files=$(find "$dir" -type f -name '*.rs')
        file_list="$file_list $files"
    else
        echo "ERROR: Directory $dir does not exist"
        exit 1  # Exit with non-zero status if directory is missing
    fi
done

# Ensure there are files to check
if [ -n "$file_list" ]; then
    # Call the function with the list of files
    check_copyright_notices $file_list
else
    echo "No .rs files found to check."
fi