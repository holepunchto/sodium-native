# Contributing

## Setup

First you need to fetch libsodium, checkout the right tag and then you need to
install dependencies:

```sh
npm run fetch-libsodium
npm install
```

## Upgrading libsodium

Please make sure to change the `version` variable in `preinstall.js` and
`postinstall.js` to match the latest sodium library version as specified by
`configure.ac`.
