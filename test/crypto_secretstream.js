const test = require('brittle')
const sodium = require('..')

test('constants', function (t) {
  t.alike(
    typeof sodium.crypto_secretstream_xchacha20poly1305_ABYTES,
    'number',
    'crypto_secretstream_xchacha20poly1305_ABYTES is number'
  )
  t.alike(
    typeof sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    'number',
    'crypto_secretstream_xchacha20poly1305_HEADERBYTES is number'
  )
  t.alike(
    typeof sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    'number',
    'crypto_secretstream_xchacha20poly1305_KEYBYTES is number'
  )
  t.alike(
    typeof sodium.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,
    'number',
    'crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX is number'
  )

  t.ok(
    typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE ===
      'number',
    'crypto_secretstream_xchacha20poly1305_TAG_MESSAGE is Buffer'
  )
  t.ok(
    typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH === 'number',
    'crypto_secretstream_xchacha20poly1305_TAG_PUSH is Buffer'
  )
  t.ok(
    typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY === 'number',
    'crypto_secretstream_xchacha20poly1305_TAG_REKEY is Buffer'
  )
  t.ok(
    typeof sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL === 'number',
    'crypto_secretstream_xchacha20poly1305_TAG_FINAL is Buffer'
  )
})

test('crypto_secretstream', function (t) {
  const state = Buffer.alloc(
    sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES
  )

  const header = Buffer.alloc(
    sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
  )
  const ad = Buffer.alloc(sodium.randombytes_uniform(100))
  sodium.randombytes_buf(ad)

  const m1 = Buffer.alloc(sodium.randombytes_uniform(1000))
  sodium.randombytes_buf(m1)

  const m2 = Buffer.alloc(sodium.randombytes_uniform(1000))
  sodium.randombytes_buf(m2)

  const m3 = Buffer.alloc(sodium.randombytes_uniform(1000))
  sodium.randombytes_buf(m3)

  const m4 = Buffer.alloc(sodium.randombytes_uniform(1000))
  sodium.randombytes_buf(m4)

  const m1_ = Buffer.from(m1)
  const m2_ = Buffer.from(m2)
  const m3_ = Buffer.from(m3)
  const m4_ = Buffer.from(m4)

  const c1 = Buffer.alloc(
    m1.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
  )
  const c2 = Buffer.alloc(
    m2.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
  )
  const c3 = Buffer.alloc(
    m3.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
  )
  const c4 = Buffer.alloc(
    m4.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
  )

  const key = Buffer.alloc(
    sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
  )
  let ret
  const tag = Buffer.alloc(
    sodium.crypto_secretstream_xchacha20poly1305_TAGBYTES,
    0xdb
  )

  sodium.crypto_secretstream_xchacha20poly1305_keygen(key)

  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
  t.unlike(
    header.toString('hex'),
    '000000000000000000000000000000000000000000000000'
  )
  ret = sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c1,
    m1,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  )
  t.alike(ret, m1.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  ret = sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c2,
    m2,
    ad.subarray(0, 0),
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  )
  t.alike(ret, m2.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  ret = sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c3,
    m3,
    ad,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  )
  t.alike(ret, m3.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  ret = sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c4,
    m4,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  )
  t.alike(ret, m4.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)

  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
  m1.fill(0)
  tag.fill(0xdb)
  ret = sodium.crypto_secretstream_xchacha20poly1305_pull(
    state,
    m1,
    tag,
    c1,
    null
  )
  t.alike(ret, c1.length - sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
  t.ok(m1.equals(m1_))

  m2.fill(0)
  tag.fill(0xdb)
  ret = sodium.crypto_secretstream_xchacha20poly1305_pull(
    state,
    m2,
    tag,
    c2,
    null
  )
  t.alike(ret, c2.length - sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
  t.ok(m2.equals(m2_))

  if (ad.length > 0) {
    t.exception.all(function () {
      sodium.crypto_secretstream_xchacha20poly1305_pull(
        state,
        m3,
        tag,
        c3,
        null
      )
    })
  }

  m3.fill(0)
  tag.fill(0xdb)
  ret = sodium.crypto_secretstream_xchacha20poly1305_pull(
    state,
    m3,
    tag,
    c3,
    ad
  )
  t.alike(ret, c3.length - sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
  t.ok(m3.equals(m3_))

  m4.fill(0)
  tag.fill(0xdb)
  ret = sodium.crypto_secretstream_xchacha20poly1305_pull(
    state,
    m4,
    tag,
    c4,
    null
  )
  t.alike(ret, c4.length - sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)
  t.ok(m4.equals(m4_))

  t.exception.all(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m4, tag, c4, null)
  }, 'previous with FINAL tag')

  t.exception.all(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, tag, c2, null)
  }, 'previous with without tag')

  t.exception.all(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(
      state,
      m2,
      tag,
      c2.subarray(
        0,
        (Math.random() * sodium.crypto_secretstream_xchacha20poly1305_ABYTES) |
          0
      ),
      null
    ) // fixme
  }, 'short ciphertext')

  t.exception.all(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(
      state,
      m2,
      tag,
      c2.subarray(0, sodium.crypto_secretstream_xchacha20poly1305_ABYTES),
      null
    )
  }, 'empty ciphertext')

  /* without explicit rekeying */

  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c1,
    m1,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY
  )
  sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c2,
    m2,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  )

  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
  tag.fill(0xdb)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m1, tag, c1, null)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY)
  tag.fill(0xdb)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, tag, c2, null)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)

  /* with explicit rekeying */

  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
  sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c1,
    m1,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  )
  sodium.crypto_secretstream_xchacha20poly1305_rekey(state)
  sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    c2,
    m2,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  )

  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
  tag.fill(0xdb)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m1, tag, c1, null)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)

  t.exception.all(function () {
    sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, tag, c2, null)
  })

  sodium.crypto_secretstream_xchacha20poly1305_rekey(state)
  tag.fill(0xdb)
  sodium.crypto_secretstream_xchacha20poly1305_pull(state, m2, tag, c2, null)
  t.alike(tag[0], sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
})
