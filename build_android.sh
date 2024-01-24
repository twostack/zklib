#!/bin/sh

export GOOS=android
export GOARCH=arm64
export CGO_ENABLED=1

#-androidapi=31
# -buildmode c-archive -o outputfilename.a 
go build -buildmode=c-shared -trimpath -o zklib.a 
# go build -buildmode=c-shared
