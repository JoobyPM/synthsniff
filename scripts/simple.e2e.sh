#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# run the program and capture all output
output="$(go run cmd/sniff4ai/main.go ./ai.generated.txt 2>&1)"

# allow an optional "./" before the filename
pattern='^🚨 (\./)?ai\.generated\.txt[[:space:]]+\(score 108\)$'

if [[ $output =~ $pattern ]]; then
  echo "Test passed"
  exit 0
else
  echo "Test failed"
  printf "Expected pattern: %s\nGot:              %s\n" "$pattern" "$output"
  exit 1
fi
