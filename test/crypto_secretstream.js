var test = require('tape')
var alloc = require('buffer-alloc')
var fill = require('buffer-fill')
var sodium = require('../')

test('constants', function (assert) {
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_ABYTES, 'number', 'crypto_secretstream_xchacha20poly1305_ABYTES is number')
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES, 'number', 'crypto_secretstream_xchacha20poly1305_HEADERBYTES is number')
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES, 'number', 'crypto_secretstream_xchacha20poly1305_KEYBYTES is number')
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX, 'number', 'crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX is number')

  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, 'number', 'crypto_secretstream_xchacha20poly1305_TAG_MESSAGE is number')
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH, 'number', 'crypto_secretstream_xchacha20poly1305_TAG_PUSH is number')
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY, 'number', 'crypto_secretstream_xchacha20poly1305_TAG_REKEY is number')
  assert.same(typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL, 'number', 'crypto_secretstream_xchacha20poly1305_TAG_FINAL is number')

  assert.end()
})

test('crypto_secretstream', function (assert) {
  var state = sodium.crypto_secretstream_xchacha20poly1305_state_new()

  var header = alloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  var ad = alloc(100 * Math.random() | 0) // Fixme
  sodium.randombytes_buf(ad)

  var m1 = alloc(1000 * Math.random() | 0) // Fixme
  sodium.randombytes_buf(m1)

  var m2 = alloc(1000 * Math.random() | 0) // Fixme
  sodium.randombytes_buf(m2)

  var m3 = alloc(1000 * Math.random() | 0) // Fixme
  sodium.randombytes_buf(m3)

  var m4 = alloc(1000 * Math.random() | 0) // Fixme
  sodium.randombytes_buf(m4)

  var m1_ = Buffer.from(m1)
  var m2_ = Buffer.from(m2)
  var m3_ = Buffer.from(m3)
  var m4_ = Buffer.from(m4)

  var c1 = alloc(m1.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  var c2 = alloc(m2.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  var c3 = alloc(m3.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  var c4 = alloc(m4.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)

  var key = alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
  sodium.crypto_secretstream_xchacha20poly1305_keygen(key)

  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c1, m1, null, 0)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c2, m2, ad.slice(0,0), 0)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c3, m3, ad, 0)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c4, m4, null, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
  fill(m1, 0)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m1, null, c1, null)
  //assert tag
  assert.ok(m1.equals(m1_))

  fill(m2, 0)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2, null)
  //assert tag
  assert.ok(m2.equals(m2_))

  if (ad.length > 0) {
    assert.throws(function () {
      sodium.crypto_secretstream_xchacha20poly1305_pull(state, m3, null, c3, null)
    })
  }

  fill(m3, 0)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m3, null, c3, ad)
  assert.ok(m3.equals(m3_))

  fill(m4, 0)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m4, null, c4, null)
  assert.ok(m4.equals(m4_))

  assert.throws(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m4, null, c4, null)
  }, 'previous with FINAL tag')

  assert.throws(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2, null)
  }, 'previous with without tag')

  assert.throws(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2.slice(0, Math.random() * sodium.crypto_secretstream_xchacha20poly1305_ABYTES | 0), null) // fixme
  }, 'short ciphertext')

  assert.throws(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2.slice(0, sodium.crypto_secretstream_xchacha20poly1305_ABYTES), null)
  }, 'empty ciphertext')

  /* without explicit rekeying */

  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c1, m1, null, sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c2, m2, null, sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)

  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m1, null, c1, null)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2, null)

  /* with explicit rekeying */

  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c1, m1, null, 0)
  sodium.crypto_secretstream_xchacha20poly1305_rekey(state)
  sodium.crypto_secretstream_xchacha20poly1305_push(state, c2, m2, null, 0)

  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m1, null, c1, null)

  assert.throws(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2, null)
  })

  sodium.crypto_secretstream_xchacha20poly1305_rekey(state)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, null, c2, null)

  assert.end()
})
