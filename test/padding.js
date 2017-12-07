var alloc = require('buffer-alloc')
var test = require('tape')
var sodium = require('../')

test('sodium_pad / sodium_unpad', function (assert) {
  for (var i = 0; i < 2000; i++) {
    var binLen = Math.random() * 200 | 0 // FIXME
    var blocksize = 1 + Math.random() * 100 | 0
    var binPaddedMaxlen = binLen + (blocksize - (binLen % blocksize))
    var bingPaddedLong = alloc(binPaddedMaxlen + 1)
    var binPaddedLen = bingPaddedLong.slice(0, binPaddedMaxlen)
    sodium.randombytes_buf(binPaddedLen)

    assert.throws(function () {
      sodium.sodium_pad(binPaddedLen.slice(0, binPaddedMaxlen - 1), binLen, blocksize)
      sodium.sodium_pad(binPaddedLen, binLen, 0)
    })

    sodium.sodium_pad(bingPaddedLong, binLen, blocksize)
    var binUnpaddedLen = sodium.sodium_pad(binPaddedLen, binLen, blocksize)
    assert.equal(binUnpaddedLen, binPaddedMaxlen)

    assert.throws(function () {
      sodium.sodium_unpad(binPaddedLen, binUnpaddedLen, binPaddedMaxlen + 1)
      sodium.sodium_unpad(binPaddedLen, binUnpaddedLen, 0)
    })

    var len2 = sodium.sodium_unpad(binPaddedLen, binUnpaddedLen, blocksize)
    assert.equal(len2, binLen)
  }

  assert.end()
})
