#!/bin/sh

# export GOOS=ios
# export GOARCH=arm64
# export SDK=iphoneos
# export CGO_CFLAGS="-fembed-bitcode"
# 
# export SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`
# export CLANG=`xcrun --sdk $SDK --find clang`
# export CARCH="arm64"  # if compiling for iPhone

#go build -o lib/ios/zklib.a

go get -d golang.org/x/mobile/cmd/gomobile

gomobile bind -target=ios/arm64 -ldflags="-s -w" -o build/ios/Zklib.xcframework
