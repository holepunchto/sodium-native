const test = require('brittle')
const sodium = require('..')

test('sodium_pad / sodium_unpad', function (t) {
  for (let i = 0; i < 2000; i++) {
    const binLen = sodium.randombytes_uniform(200)
    const blocksize = 1 + sodium.randombytes_uniform(100)
    const binPaddedMaxlen = binLen + (blocksize - (binLen % blocksize))
    const bingPaddedLong = Buffer.alloc(binPaddedMaxlen + 1)
    const binPaddedLen = bingPaddedLong.subarray(0, binPaddedMaxlen)
    sodium.randombytes_buf(binPaddedLen)

    const smallThrow = didThrow(function () {
      sodium.sodium_pad(
        binPaddedLen.subarray(0, binPaddedMaxlen - 1),
        binLen,
        blocksize
      )
    })
    if (smallThrow === false) t.fail('did not throw')

    const zeroThrow = didThrow(function () {
      sodium.sodium_pad(binPaddedLen, binLen, 0)
    })
    if (zeroThrow === false) t.fail('did not throw')

    sodium.sodium_pad(bingPaddedLong, binLen, blocksize)
    const binUnpaddedLen = sodium.sodium_pad(binPaddedLen, binLen, blocksize)
    if (binUnpaddedLen !== binPaddedMaxlen)
      t.fail('binUnpaddedLen was not same')

    const largeThrow = didThrow(function () {
      sodium.sodium_unpad(binPaddedLen, binUnpaddedLen, binPaddedMaxlen + 1)
    })
    if (largeThrow === false) t.fail('did not throw')

    const emptyThrow = didThrow(function () {
      sodium.sodium_unpad(binPaddedLen, binUnpaddedLen, 0)
    })
    if (emptyThrow === false) t.fail('did not throw')

    const len2 = sodium.sodium_unpad(binPaddedLen, binUnpaddedLen, blocksize)
    if (len2 !== binLen) t.fail('len2 was not same')
  }

  t.pass()
})

function didThrow(fn) {
  try {
    fn()
    return false
  } catch (ex) {
    return true
  }
}
