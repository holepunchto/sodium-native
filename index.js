require('libsodium-prebuilt')
var sodium = require('node-gyp-build')(__dirname)

module.exports = sodium
