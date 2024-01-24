#!/bin/sh

export GOOS=ios
export GOARCH=arm64
export SDK=iphonesimulator
CGO_CFLAGS="-fembed-bitcode"

go build -buildmode=c-shared
