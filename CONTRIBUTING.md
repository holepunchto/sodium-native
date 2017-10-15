# Contributing

## Setup

First you need to fetch libsodium, checkout the right tag and then you need to
install dependencies:

```sh
npm run fetch-libsodium
npm install
```

## Release

Prior to release, you need to get prebuilds from Windows, macOS and Linux,
collect all the artefacts in a tar ball and publish to npm.

The tree should look like this in the end, with [various `electron-*.node` and
`node-*.node` versions](https://github.com/lgeiger/node-abi/blob/master/index.js#L51-L65)
asterisk being replaced by ABI version:

```
prebuilds
├── darwin-x64
│   ├── electron-*.node
│   ├── libsodium.dylib
│   └── node-*.node
├── linux-ia32
│   ├── electron-*.node
│   ├── libsodium.so.18
│   └── node-*.node
├── linux-x64
│   ├── electron-*.node
│   ├── libsodium.so.18
│   └── node-*.node
├── win32-ia32
│   ├── electron-*.node
│   ├── libsodium.dll
│   └── node-*.node
└── win32-x64
    ├── electron-*.node
    ├── libsodium.dll
    └── node-*.node
```

### Windows

For Windows you need both 64-bit and 32-bit builds:

```sh
npm run prebuild
npm run prebuild-ia32
```

### macOS

For macOS you only need 64-bit builds:

```sh
npm run prebuild
```

### Linux, FreeBSD and OpenBSD

For these platforms you need both 64-bit and 32-bit builds:

```sh
npm run prebuild
npm run prebuild-ia32
```
