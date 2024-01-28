#!/bin/sh

go get -d golang.org/x/mobile/cmd/gomobile

gomobile bind -target=ios/arm64 -ldflags="-s -w" -o build/ios/Zklib.xcframework

codesign --sign "32XLPKQ5TF" build/ios/Zklib.xcframework
