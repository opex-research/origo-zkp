#!/bin/bash

# Navigate to the root directory of the project
cd circuits || exit

# Find and run tests in each subdirectory that contains Go files
find . -type f -name '*.go' | sed -r 's|/[^/]+$||' | sort -u | while read -r d; do
    go test -v "$d"
done
