#!/bin/bash
set -e

echo -e "\033[1m== go vet (static analysis) ==\033[0m"
go vet ./...
echo -e "\033[32mPASS\033[0m  go vet clean"

echo -e "\n\033[1m== go test (unit & integration tests) ==\033[0m"
go test -v ./...
echo -e "\033[32mPASS\033[0m  all go tests passed"

echo -e "\n\033[1m== go build (compiling binary) ==\033[0m"
go build -o burpsy ./cmd/burpsy
echo -e "\033[32mPASS\033[0m  burpsy compiled successfully with zero warnings/errors"

echo -e "\n\033[1;32m######## GO PORT VERIFIED SUCCESSFULLY ########\033[0m"
