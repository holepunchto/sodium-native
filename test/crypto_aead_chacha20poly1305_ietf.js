var test = require('tape')
var sodium = require('..')

test('constants', function (assert) {
  assert.equal(typeof sodium.crypto_aead_chacha20poly1305_ietf_ABYTES, 'number')
  assert.equal(typeof sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES, 'number')
  assert.equal(typeof sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 'number')
  assert.equal(typeof sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES, 'number')
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES, 0)
  assert.equal(typeof sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 'bigint')
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 0x3fffffffc0n) // to make sure, see note in binding.cc

  assert.end()
})

test('ported from libsodium', function (assert) { /* eslint-disable */
  var mlen = 114
  var adlen = 12
  var clen = mlen + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES

  var firstkey = Buffer.from([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
  ])

  var message = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  var m = sodium.sodium_malloc(mlen)
  var nonce = Buffer.from([
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
  ])
  assert.equal(nonce.length, sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)

  var ad = Buffer.from([
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
  ])
  assert.equal(ad.length, adlen)

  var c = sodium.sodium_malloc(clen)
  var detached_c = sodium.sodium_malloc(mlen)

  var mac = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)

  var m2 = sodium.sodium_malloc(mlen)

  var found_clen = 0
  var found_maclen = 0
  var m2len = 0

  var i = 0

  assert.equal(message.length, mlen)
  message.copy(m)

  found_clen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, ad, null, nonce, firstkey)
  assert.equal(found_clen, mlen + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)

  var exp1 = Buffer.from([
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
    0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
  ])

  assert.same(c, exp1)

  found_maclen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(detached_c, mac, m, ad, null, nonce, firstkey)

  assert.equal(found_maclen, sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  assert.same(detached_c, c.slice(0, mlen))

  m2len = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c, ad, nonce, firstkey)
  assert.equal(m2len, mlen)

  assert.same(m, m2)

  m2.fill(0)
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m2, null, c.slice(0, mlen), mac, ad, nonce, firstkey)

  assert.same(m, m2)

  for (i = 0; i < clen; i++) {
    c[i] ^= (i + 1)
    assert.throws(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c, ad, nonce, firstkey))
    if (m.equals(m2)) assert.fail()
    c[i] ^= (i + 1)
  }

  found_clen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, null, null, nonce, firstkey)
  assert.equal(found_clen, clen)

  var exp2 = Buffer.from([
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x6a, 0x23, 0xa4, 0x68, 0x1f, 0xd5,
    0x94, 0x56, 0xae, 0xa1, 0xd2, 0x9f, 0x82, 0x47, 0x72, 0x16
  ])

  assert.same(c, exp2)

  m2len = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c, null, nonce, firstkey)
  assert.equal(m2len, mlen)

  assert.same(m2, m)

  m.copy(c)

  found_clen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, c.slice(0, mlen), null, null, nonce, firstkey);

  assert.equal(found_clen, clen, 'clen is properly set (adlen=0)')

  var exp3 = Buffer.from([
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x6a, 0x23, 0xa4, 0x68, 0x1f, 0xd5,
    0x94, 0x56, 0xae, 0xa1, 0xd2, 0x9f, 0x82, 0x47, 0x72, 0x16
  ])

  assert.same(c, exp3)

  var decrypted = sodium.sodium_malloc(c.byteLength - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  m2len = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, null, c, null, nonce, firstkey)
  assert.equal(m2len, mlen, 'm2len is properly set (adlen=0)')

  assert.same(m, decrypted, 'm == c (adlen=0)')

  assert.end()
  /* eslint-enable */
})

test('keygen', function (assert) {
  var key1 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  var key2 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)

  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key1)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key2)

  assert.notSame(key1, key2)
  assert.end()
})

test('different keys', function (assert) {
  var m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  var key1 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  var key2 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key1)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key2)

  var nonce = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  var clen = m.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  var c1 = sodium.sodium_malloc(clen)
  var c2 = sodium.sodium_malloc(clen)

  var m1 = sodium.sodium_malloc(m.byteLength)
  var m2 = sodium.sodium_malloc(m.byteLength)

  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c1, m, null, null, nonce, key1), clen)
  assert.notOk(c1.equals(c2))
  assert.notOk(c1.equals(m))
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c2, m, null, null, nonce, key2), clen)
  assert.notOk(c1.equals(c2))
  assert.notOk(c2.equals(m))

  assert.throws(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, nonce, key2))
  assert.throws(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, nonce, key1))

  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, nonce, key1), m.byteLength)
  assert.ok(m.equals(m1))
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, nonce, key2), m.byteLength)
  assert.ok(m.equals(m2))

  assert.end()
})

test('different nonce', function (assert) {
  var m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  var key = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key)

  var n1 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  var n2 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(n1)
  sodium.randombytes_buf(n2)

  var clen = m.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  var c1 = sodium.sodium_malloc(clen)
  var c2 = sodium.sodium_malloc(clen)

  var m1 = sodium.sodium_malloc(m.byteLength)
  var m2 = sodium.sodium_malloc(m.byteLength)

  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c1, m, null, null, n1, key), clen)
  assert.notOk(c1.equals(c2))
  assert.notOk(c1.equals(m))
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c2, m, null, null, n2, key), clen)
  assert.notOk(c1.equals(c2))
  assert.notOk(c2.equals(m))

  assert.throws(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, n2, key))
  assert.throws(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, n1, key))

  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, n1, key), m.byteLength)
  assert.ok(m.equals(m1))
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, n2, key), m.byteLength)
  assert.ok(m.equals(m2))

  assert.end()
})

test('detached -> non-detached', function (assert) {
  var m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  var key = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key)

  var nonce = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  var mac = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  var clen = m.byteLength
  var c = sodium.sodium_malloc(clen)

  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, m, null, null, nonce, key), mac.byteLength)

  var m1 = sodium.sodium_malloc(m.byteLength)
  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, Buffer.concat([c, mac]), null, nonce, key), m.byteLength)

  assert.same(m, m1)

  assert.end()
})

test('non-detached -> detached', function (assert) {
  var m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  var key = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key)

  var nonce = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  var clen = m.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  var c = sodium.sodium_malloc(clen)

  assert.equal(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, null, null, nonce, key), c.byteLength)

  var m1 = sodium.sodium_malloc(m.byteLength)
  var csub = c.subarray(0, clen - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  var macsub = c.subarray(csub.byteLength)
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m1, null, csub, macsub, null, nonce, key)

  assert.same(m, m1)

  assert.end()
})

/**
 * Need to test in-place encryption
 * detach can talk to non detach
 * encrypt - decrypt
 * different nonce
 * different key
 * return values
 */
