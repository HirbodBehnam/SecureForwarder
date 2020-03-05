@echo off
set CGO_ENABLED=1
set GOOS=android
mkdir android
mkdir android\armeabi-v7a
mkdir android\arm64-v8a
mkdir android\x86
mkdir android\x86_64

echo "Building for armeabi-v7a"
set CC=F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi21-clang
set GOARCH=arm
set GOARM=7
go build
F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\arm-linux-androideabi-strip.exe SecureForwarder
move SecureForwarder android\armeabi-v7a\libsf.so

echo "Building for arm64-v8a"
set CC=F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android22-clang
set GOARCH=arm64
go build
F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android-strip.exe SecureForwarder
move SecureForwarder android\arm64-v8a\libsf.so

echo "Building for x86"
set CC=F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\i686-linux-android21-clang
set GOARCH=386
go build
F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\i686-linux-android-strip.exe SecureForwarder
move SecureForwarder android\x86\libsf.so

echo "Building for x86_64"
set CC=F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\x86_64-linux-android21-clang
set GOARCH=amd64
go build
F:\SDK\ndk-bundle\toolchains\llvm\prebuilt\windows-x86_64\bin\x86_64-linux-android-strip.exe SecureForwarder
move SecureForwarder android\x86_64\libsf.so