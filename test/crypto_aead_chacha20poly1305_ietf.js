const test = require('brittle')
const sodium = require('..')

test('constants', function (t) {
  t.is(typeof sodium.crypto_aead_chacha20poly1305_ietf_ABYTES, 'number')
  t.is(typeof sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES, 'number')
  t.is(typeof sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 'number')
  t.is(typeof sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES, 'number')
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES, 0)
  t.is(typeof sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 'number')
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 0x3fffffffc0) // to make sure, see note in binding.cc
})

test('ported from libsodium', function (t) {
  const mlen = 114
  const adlen = 12
  const clen = mlen + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES

  const firstkey = Buffer.from([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
  ])

  const message = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  const m = sodium.sodium_malloc(mlen)
  const nonce = Buffer.from([
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
  ])
  t.is(nonce.length, sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)

  const ad = Buffer.from([
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
  ])
  t.is(ad.length, adlen)

  const c = sodium.sodium_malloc(clen)
  const detachedc = sodium.sodium_malloc(mlen)

  const mac = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)

  const m2 = sodium.sodium_malloc(mlen)

  let foundclen = 0
  let foundmaclen = 0
  let m2len = 0

  let i = 0

  t.is(message.length, mlen)
  message.copy(m)

  foundclen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, ad, null, nonce, firstkey)
  t.is(foundclen, mlen + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)

  const exp1 = Buffer.from([
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
  exp1.secure = true

  t.alike(c, exp1)

  foundmaclen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(detachedc, mac, m, ad, null, nonce, firstkey)

  t.is(foundmaclen, sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  const exp0 = c.subarray(0, mlen)
  exp0.secure = true
  t.alike(detachedc, exp0)

  m2len = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c, ad, nonce, firstkey)
  t.is(m2len, mlen)

  t.alike(m, m2)

  m2.fill(0)
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m2, null, c.subarray(0, mlen), mac, ad, nonce, firstkey)

  t.alike(m, m2)

  for (i = 0; i < clen; i++) {
    c[i] ^= (i + 1)
    t.exception.all(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c, ad, nonce, firstkey))
    if (m.equals(m2)) t.fail()
    c[i] ^= (i + 1)
  }

  foundclen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, null, null, nonce, firstkey)
  t.is(foundclen, clen)

  const exp2 = Buffer.from([
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
  exp2.secure = true

  t.alike(c, exp2)

  m2len = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c, null, nonce, firstkey)
  t.is(m2len, mlen)

  t.alike(m2, m)

  m.copy(c)

  foundclen = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, c.subarray(0, mlen), null, null, nonce, firstkey)

  t.is(foundclen, clen, 'clen is properly set (adlen=0)')

  const exp3 = Buffer.from([
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
  exp3.secure = true

  t.alike(c, exp3)

  const decrypted = sodium.sodium_malloc(c.byteLength - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  m2len = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, null, c, null, nonce, firstkey)
  t.is(m2len, mlen, 'm2len is properly set (adlen=0)')

  t.alike(m, decrypted, 'm == c (adlen=0)')
})

test('keygen', function (t) {
  const key1 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  const key2 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)

  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key1)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key2)

  t.unlike(key1, key2)
})

test('different keys', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  const key1 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  const key2 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key1)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key2)

  const nonce = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  const clen = m.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  const c1 = sodium.sodium_malloc(clen)
  const c2 = sodium.sodium_malloc(clen)

  const m1 = sodium.sodium_malloc(m.byteLength)
  const m2 = sodium.sodium_malloc(m.byteLength)

  t.is(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c1, m, null, null, nonce, key1), clen)
  t.absent(c1.equals(c2))
  t.absent(c1.equals(m))
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c2, m, null, null, nonce, key2), clen)
  t.absent(c1.equals(c2))
  t.absent(c2.equals(m))

  t.exception.all(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, nonce, key2))
  t.exception.all(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, nonce, key1))

  t.is(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, nonce, key1), m.byteLength)
  t.ok(m.equals(m1))
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, nonce, key2), m.byteLength)
  t.ok(m.equals(m2))
})

test('different nonce', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  const key = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key)

  const n1 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  const n2 = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(n1)
  sodium.randombytes_buf(n2)

  const clen = m.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  const c1 = sodium.sodium_malloc(clen)
  const c2 = sodium.sodium_malloc(clen)

  const m1 = sodium.sodium_malloc(m.byteLength)
  const m2 = sodium.sodium_malloc(m.byteLength)

  t.is(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c1, m, null, null, n1, key), clen)
  t.absent(c1.equals(c2))
  t.absent(c1.equals(m))
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c2, m, null, null, n2, key), clen)
  t.absent(c1.equals(c2))
  t.absent(c2.equals(m))

  t.exception.all(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, n2, key))
  t.exception.all(_ => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, n1, key))

  t.is(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, c1, null, n1, key), m.byteLength)
  t.ok(m.equals(m1))
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m2, null, c2, null, n2, key), m.byteLength)
  t.ok(m.equals(m2))
})

test('detached -> non-detached', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')
  m.secure = true

  const key = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key)

  const nonce = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  const mac = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  const clen = m.byteLength
  const c = sodium.sodium_malloc(clen)

  t.is(sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, m, null, null, nonce, key), mac.byteLength)

  const m1 = sodium.sodium_malloc(m.byteLength)
  t.is(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m1, null, Buffer.concat([c, mac]), null, nonce, key), m.byteLength)

  t.alike(m, m1)
})

test('non-detached -> detached', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')
  m.secure = true

  const key = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_keygen(key)

  const nonce = sodium.sodium_malloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  const clen = m.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  const c = sodium.sodium_malloc(clen)

  t.is(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, null, null, nonce, key), c.byteLength)

  const m1 = sodium.sodium_malloc(m.byteLength)
  const csub = c.subarray(0, clen - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  const macsub = c.subarray(csub.byteLength)
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m1, null, csub, macsub, null, nonce, key)

  t.alike(m, m1)
})

/**
 * Need to test in-place encryption
 * detach can talk to non detach
 * encrypt - decrypt
 * different nonce
 * different key
 * return values
 */
