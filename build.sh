#!/bin/bash

# Exit on any error
set -e

# Navigate to the root directory of the project
cd circuits || exit

# Find all directories with .go files and build them
find . -type f -name '*.go' | sed -r 's|/[^/]+$||' | sort -u | while read -r d; do
    echo "Building $d..."
    go build -v "$d"
done
