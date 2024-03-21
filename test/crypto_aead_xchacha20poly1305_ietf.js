const test = require('brittle')
const sodium = require('..')

test('constants', function (t) {
  t.is(typeof sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES, 'number')
  t.is(typeof sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 'number')
  t.is(typeof sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 'number')
  t.is(typeof sodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES, 'number')
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES, 0)
  t.is(typeof sodium.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX, 'number')
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX, Number.MAX_SAFE_INTEGER) // to make sure, see note in binding.c
})

test('ported from libsodium', function (t) {
  const mlen = 114
  const adlen = 12
  const clen = mlen + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

  const firstkey = Buffer.from([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
  ])

  const message = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  const m = sodium.sodium_malloc(mlen)
  const nonce = new Uint8Array([
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53
  ])
  t.is(nonce.length, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)

  const ad = Buffer.from([
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
  ])
  t.is(ad.length, adlen)

  const c = sodium.sodium_malloc(clen)
  const detachedc = sodium.sodium_malloc(mlen)

  const key2 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  const mac = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)

  const m2 = sodium.sodium_malloc(mlen)

  let foundclen = 0
  let foundmaclen = 0
  let m2len = 0

  let i = 0

  t.is(message.length, mlen)
  message.copy(m)

  foundclen = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, m, ad, null, nonce, firstkey)
  t.is(foundclen, mlen + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)

  const exp1 = Buffer.from([
    0xf8, 0xeb, 0xea, 0x48, 0x75, 0x04, 0x40, 0x66,
    0xfc, 0x16, 0x2a, 0x06, 0x04, 0xe1, 0x71, 0xfe,
    0xec, 0xfb, 0x3d, 0x20, 0x42, 0x52, 0x48, 0x56,
    0x3b, 0xcf, 0xd5, 0xa1, 0x55, 0xdc, 0xc4, 0x7b,
    0xbd, 0xa7, 0x0b, 0x86, 0xe5, 0xab, 0x9b, 0x55,
    0x00, 0x2b, 0xd1, 0x27, 0x4c, 0x02, 0xdb, 0x35,
    0x32, 0x1a, 0xcd, 0x7a, 0xf8, 0xb2, 0xe2, 0xd2,
    0x50, 0x15, 0xe1, 0x36, 0xb7, 0x67, 0x94, 0x58,
    0xe9, 0xf4, 0x32, 0x43, 0xbf, 0x71, 0x9d, 0x63,
    0x9b, 0xad, 0xb5, 0xfe, 0xac, 0x03, 0xf8, 0x0a,
    0x19, 0xa9, 0x6e, 0xf1, 0x0c, 0xb1, 0xd1, 0x53,
    0x33, 0xa8, 0x37, 0xb9, 0x09, 0x46, 0xba, 0x38,
    0x54, 0xee, 0x74, 0xda, 0x3f, 0x25, 0x85, 0xef,
    0xc7, 0xe1, 0xe1, 0x70, 0xe1, 0x7e, 0x15, 0xe5,
    0x63, 0xe7, 0x76, 0x01, 0xf4, 0xf8, 0x5c, 0xaf,
    0xa8, 0xe5, 0x87, 0x76, 0x14, 0xe1, 0x43, 0xe6,
    0x84, 0x20
  ])
  exp1.secure = true

  t.alike(c, exp1)

  foundmaclen = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(detachedc, mac, m, ad, null, nonce, firstkey)

  t.is(foundmaclen, sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
  const exp0 = c.slice(0, mlen)
  exp0.secure = true
  t.alike(detachedc, exp0)

  m2len = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c, ad, nonce, firstkey)
  t.is(m2len, mlen)

  t.alike(m, m2)

  m2.fill(0)
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m2, null, c.slice(0, mlen), mac, ad, nonce, firstkey)

  t.alike(m, m2)

  for (i = 0; i < clen; i++) {
    c[i] ^= (i + 1)
    t.exception.all(_ => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c, ad, nonce, firstkey))
    if (m.equals(m2)) t.fail()
    c[i] ^= (i + 1)
  }

  foundclen = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, m, null, null, nonce, firstkey)
  t.is(foundclen, clen)

  const exp2 = Buffer.from([
    0xf8, 0xeb, 0xea, 0x48, 0x75, 0x04, 0x40, 0x66,
    0xfc, 0x16, 0x2a, 0x06, 0x04, 0xe1, 0x71, 0xfe,
    0xec, 0xfb, 0x3d, 0x20, 0x42, 0x52, 0x48, 0x56,
    0x3b, 0xcf, 0xd5, 0xa1, 0x55, 0xdc, 0xc4, 0x7b,
    0xbd, 0xa7, 0x0b, 0x86, 0xe5, 0xab, 0x9b, 0x55,
    0x00, 0x2b, 0xd1, 0x27, 0x4c, 0x02, 0xdb, 0x35,
    0x32, 0x1a, 0xcd, 0x7a, 0xf8, 0xb2, 0xe2, 0xd2,
    0x50, 0x15, 0xe1, 0x36, 0xb7, 0x67, 0x94, 0x58,
    0xe9, 0xf4, 0x32, 0x43, 0xbf, 0x71, 0x9d, 0x63,
    0x9b, 0xad, 0xb5, 0xfe, 0xac, 0x03, 0xf8, 0x0a,
    0x19, 0xa9, 0x6e, 0xf1, 0x0c, 0xb1, 0xd1, 0x53,
    0x33, 0xa8, 0x37, 0xb9, 0x09, 0x46, 0xba, 0x38,
    0x54, 0xee, 0x74, 0xda, 0x3f, 0x25, 0x85, 0xef,
    0xc7, 0xe1, 0xe1, 0x70, 0xe1, 0x7e, 0x15, 0xe5,
    0x63, 0xe7, 0xe0, 0x96, 0xe0, 0x33, 0xd9, 0x1b,
    0x63, 0xf7, 0xac, 0x92, 0xe9, 0x97, 0x2e, 0x0d,
    0x43, 0xe5
  ])
  exp2.secure = true

  t.alike(c, exp2)

  m2len = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c, null, nonce, firstkey)
  t.is(m2len, mlen)

  t.alike(m2, m)

  m.copy(c)

  foundclen = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, c.slice(0, mlen), null, null, nonce, firstkey)

  t.is(foundclen, clen, 'clen is properly set (adlen=0)')

  const exp3 = Buffer.from([
    0xf8, 0xeb, 0xea, 0x48, 0x75, 0x04, 0x40, 0x66,
    0xfc, 0x16, 0x2a, 0x06, 0x04, 0xe1, 0x71, 0xfe,
    0xec, 0xfb, 0x3d, 0x20, 0x42, 0x52, 0x48, 0x56,
    0x3b, 0xcf, 0xd5, 0xa1, 0x55, 0xdc, 0xc4, 0x7b,
    0xbd, 0xa7, 0x0b, 0x86, 0xe5, 0xab, 0x9b, 0x55,
    0x00, 0x2b, 0xd1, 0x27, 0x4c, 0x02, 0xdb, 0x35,
    0x32, 0x1a, 0xcd, 0x7a, 0xf8, 0xb2, 0xe2, 0xd2,
    0x50, 0x15, 0xe1, 0x36, 0xb7, 0x67, 0x94, 0x58,
    0xe9, 0xf4, 0x32, 0x43, 0xbf, 0x71, 0x9d, 0x63,
    0x9b, 0xad, 0xb5, 0xfe, 0xac, 0x03, 0xf8, 0x0a,
    0x19, 0xa9, 0x6e, 0xf1, 0x0c, 0xb1, 0xd1, 0x53,
    0x33, 0xa8, 0x37, 0xb9, 0x09, 0x46, 0xba, 0x38,
    0x54, 0xee, 0x74, 0xda, 0x3f, 0x25, 0x85, 0xef,
    0xc7, 0xe1, 0xe1, 0x70, 0xe1, 0x7e, 0x15, 0xe5,
    0x63, 0xe7, 0xe0, 0x96, 0xe0, 0x33, 0xd9, 0x1b,
    0x63, 0xf7, 0xac, 0x92, 0xe9, 0x97, 0x2e, 0x0d,
    0x43, 0xe5
  ])
  exp3.secure = true

  t.alike(c, exp3)

  const decrypted = sodium.sodium_malloc(c.byteLength - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
  m2len = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, null, c, null, nonce, firstkey)
  t.is(m2len, mlen, 'm2len is properly set (adlen=0)')

  t.alike(m, decrypted, 'm == c (adlen=0)')

  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key2)
  t.exception.all(_ => (m2len = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, null, c, null, nonce, key2)))
})

test('keygen', function (t) {
  const key1 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  const key2 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)

  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key1)
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key2)

  t.unlike(key1, key2)
})

test('different keys', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  const key1 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  const key2 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key1)
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key2)

  const nonce = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  const clen = m.byteLength + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  const c1 = sodium.sodium_malloc(clen)
  const c2 = sodium.sodium_malloc(clen)

  const m1 = sodium.sodium_malloc(m.byteLength)
  const m2 = sodium.sodium_malloc(m.byteLength)

  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c1, m, null, null, nonce, key1), clen)
  t.absent(c1.equals(c2))
  t.absent(c1.equals(m))
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c2, m, null, null, nonce, key2), clen)
  t.absent(c1.equals(c2))
  t.absent(c2.equals(m))

  t.exception.all(_ => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m1, null, c1, null, nonce, key2))
  t.exception.all(_ => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c2, null, nonce, key1))

  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m1, null, c1, null, nonce, key1), m.byteLength)
  t.ok(m.equals(m1))
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c2, null, nonce, key2), m.byteLength)
  t.ok(m.equals(m2))
})

test('different nonce', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')

  const key = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key)

  const n1 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const n2 = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(n1)
  sodium.randombytes_buf(n2)

  const clen = m.byteLength + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  const c1 = sodium.sodium_malloc(clen)
  const c2 = sodium.sodium_malloc(clen)

  const m1 = sodium.sodium_malloc(m.byteLength)
  const m2 = sodium.sodium_malloc(m.byteLength)

  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c1, m, null, null, n1, key), clen)
  t.absent(c1.equals(c2))
  t.absent(c1.equals(m))
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c2, m, null, null, n2, key), clen)
  t.absent(c1.equals(c2))
  t.absent(c2.equals(m))

  t.exception.all(_ => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m1, null, c1, null, n2, key))
  t.exception.all(_ => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c2, null, n1, key))

  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m1, null, c1, null, n1, key), m.byteLength)
  t.ok(m.equals(m1))
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m2, null, c2, null, n2, key), m.byteLength)
  t.ok(m.equals(m2))
})

test('detached -> non-detached', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')
  m.secure = true

  const key = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key)

  const nonce = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  const mac = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
  const clen = m.byteLength
  const c = sodium.sodium_malloc(clen)

  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, m, null, null, nonce, key), mac.byteLength)

  const m1 = sodium.sodium_malloc(m.byteLength)
  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m1, null, Buffer.concat([c, mac]), null, nonce, key), m.byteLength)

  t.alike(m, m1)
})

test('non-detached -> detached', function (t) {
  const m = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')
  m.secure = true

  const key = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key)

  const nonce = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  sodium.randombytes_buf(nonce)

  const clen = m.byteLength + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  const c = sodium.sodium_malloc(clen)

  t.is(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, m, null, null, nonce, key), c.byteLength)

  const m1 = sodium.sodium_malloc(m.byteLength)
  const csub = c.subarray(0, clen - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
  const macsub = c.subarray(csub.byteLength)
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m1, null, csub, macsub, null, nonce, key)

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
