# Contributing

## Setup

The node script in deps/bin.js handles fetching source code, windows prebuild DLL
and building the initial setup on all platforms. To trigger either run `npm install`,
or call it manually (it has no npm dependencies).

## Release

* Change the title of "Next" to the next version in the changelog
* Update the link to the current released docs version in the README file
* Tag a new release and push to Github, triggering CI services to test and build
  artifacts for windows (32 and 64 bit), MacOS (64 bit) and Linux (64 bit).
  NOTE: for now this step is done manually as Github actions has disabled the ubuntu 16 runner we use for compat.
* Produce `arm7l` artifacts. We use a Raspberry 3+ Model B with raspbian for
  this, following the steps from `.travis.yml` with stock version of `gcc`,
  `autotools` and `make`:
  ```
  npm install
  npm test
  npm run prebuild
  tar --create --verbose --file="`git describe --tags`-linux-`uname -m`.tar" --directory "./prebuilds" .
  ```
  This tar file should be uploaded to Github Release like the artifacts produced
  by CI services.
* Clean out the repository on your local computer:
  ```
  git clean -x -d -f
  ```
* Add prebuild artifacts:
  - `mkdir prebuilds`
  - Download all artifacts from Github Releases
  - Extract tar archives and zip files into `prebuilds`
* `npm publish`
* Enjoy!
