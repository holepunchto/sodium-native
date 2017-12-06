var alloc = require('buffer-alloc')
var test = require('tape')
var sodium = require('../')

test('sodium_pad / sodium_unpad', function (assert) {
  for (var i = 0; i < 2000; i++) {
    var bin_len = Math.random() * 200 | 0 // FIXME
    var blocksize = 1 + Math.random() * 100 | 0
    var bin_padded_maxlen = bin_len + (blocksize - (bin_len % blocksize))
    var bin_padded_long = alloc(bin_padded_maxlen + 1)
    var bin_padded = bin_padded_long.slice(0, bin_padded_maxlen)
    sodium.randombytes_buf(bin_padded)

    assert.throws(function () {
      sodium.sodium_pad(bin_padded.slice(0, bin_padded_maxlen - 1), bin_len, blocksize)
      sodium.sodium_pad(bin_padded, bin_len, 0)
    })

    sodium.sodium_pad(bin_padded_long, bin_len, blocksize)
    var bin_padded_len = sodium.sodium_pad(bin_padded, bin_len, blocksize)
    assert.equal(bin_padded_len, bin_padded_maxlen)

    assert.throws(function () {
      sodium.sodium_unpad(bin_padded, bin_padded_len, bin_padded_maxlen + 1)
      sodium.sodium_unpad(bin_padded, bin_padded_len, 0)
    })

    var len2 = sodium.sodium_unpad(bin_padded, bin_padded_len, blocksize)
    assert.equal(len2, bin_len)

  }

  assert.end()
})
