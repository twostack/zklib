#!/bin/sh

export GOOS=android
export GOARCH=arm64
export CGO_ENABLED=1
# 
# #-androidapi=31
# # -buildmode c-archive -o outputfilename.a 
# go build -buildmode=c-shared 
# # -o lib/android/zklib.apk
# # go build -buildmode=c-shared

go get -d golang.org/x/mobile/cmd/gomobile

gomobile bind -target=android/arm64 -androidapi=31 -o build/android/zklib.aar

