#!/bin/bash

source .github/env.sh

go run ./infra/build/build.go
sudo cp -f build/current/sc /usr/local/bin/
