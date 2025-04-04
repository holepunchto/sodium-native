const test = require('brittle')
const sodium = require('..')
const { isBare } = require('which-runtime')

const tests = [
  ['0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000', '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d'],
  ['0000000000000000000000000000000000000000000000000000000000000001', '0000000000000000', '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae5469633aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a096d68b9ff7b57e7090f880392effd5b297a83bbaf2fbe8cf5d4618965e3dc776'],
  ['0000000000000000000000000000000000000000000000000000000000000000', '0000000000000001', 'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757283547e3d3d30ee0371c1e6025ff4c91b794a291cf7568d48ff84b37329e2730b12738a072a2b2c7169e326fe4893a7b2421bb910b79599a7ce4fbaee86be427c5ee0e8225eb6f48231fd504939d59eac8bd106cc138779b893c54da8758f62a'],
  ['0000000000000000000000000000000000000000000000000000000000000000', '0100000000000000', 'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b5305e5e44aff19b235936144675efbe4409eb7e8e5f1430f5f5836aeb49bb5328b017c4b9dc11f8a03863fa803dc71d5726b2b6b31aa32708afe5af1d6b690584d58792b271e5fdb92c486051c48b79a4d48a109bb2d0477956e74c25e93c3c2'],
  ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '0001020304050607', 'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025']
]

const vectors = [
  'f7010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
  'f798a189040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404',
  'f798a189f195e6070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707',
  'f798a189f195e66982100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a',
  'f798a189f195e66982105ffb640d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d',
  'f798a189f195e66982105ffb640bb775101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010',
  'f798a189f195e66982105ffb640bb7757f579d131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313',
  'f798a189f195e66982105ffb640bb7757f579da31602161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac561c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac31f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b73252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b4641282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c92b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c94400492e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f159163a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2b3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d',
  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040'
]

test('constants', function (t) {
  t.ok(sodium.crypto_stream_chacha20_KEYBYTES > 0)
  t.ok(sodium.crypto_stream_chacha20_NONCEBYTES > 0)
  t.ok(sodium.crypto_stream_chacha20_MESSAGEBYTES_MAX > 0)
})

test('libsodium crypto_stream_chacha20', function (t) {
  const key = Buffer.alloc(sodium.crypto_stream_chacha20_KEYBYTES)
  const nonce = Buffer.alloc(sodium.crypto_stream_chacha20_NONCEBYTES)

  const out = Buffer.alloc(160)

  for (let i = 0; i < tests.length; i++) {
    key.write(tests[i][0], 0, key.byteLength, 'hex')
    nonce.write(tests[i][1], 0, nonce.byteLength, 'hex')
    sodium.crypto_stream_chacha20(out, nonce, key)
    t.alike(out, Buffer.from(tests[i][2], 'hex'))
    for (let plen = 0; plen < out.byteLength; plen++) {
      const part = Buffer.alloc(plen)
      sodium.crypto_stream_chacha20_xor(part, out.subarray(0, plen), nonce, key)
      if (part.every(b => b === 0) === false) return t.fail()
    }
  }

  for (let plen = 1, i = 0; plen < 66; plen += 3, i++) {
    out.fill(plen & 0xff)
    sodium.crypto_stream_chacha20(out.subarray(0, plen), nonce, key)
    if (out.equals(Buffer.from(vectors[i], 'hex')) === false) return t.fail()
  }

  sodium.randombytes_buf(out)
  sodium.crypto_stream_chacha20(out, nonce, key)
  t.alike(out, Buffer.from('f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025', 'hex'))

  t.execution(() => sodium.crypto_stream_chacha20(out.subarray(0, 0), nonce, key))
  t.execution(() => sodium.crypto_stream_chacha20_xor(out.subarray(0, 0), Buffer.alloc(0), nonce, key))
  t.execution(() => sodium.crypto_stream_chacha20_xor(out.subarray(0, 0), Buffer.alloc(0), nonce, key))
  t.execution(() => sodium.crypto_stream_chacha20_xor_ic(out.subarray(0, 0), Buffer.alloc(0), nonce, 1, key))

  out.fill(0x42)
  sodium.crypto_stream_chacha20_xor(out, out, nonce, key)
  t.alike(out, Buffer.from('b5dae3cbb3d7a42bc0521db92649f5373d15dfe15440bed1ae43ee14ba18818376e616393179040372008b06420b552b4791fc1ba85e11b31b54571e69aa66587a42c9d864fe77d65c6606553ec89c24cb9cd7640bc49b1acbb922aa046b8bffd818895e835afc147cfbf1e6e630ba6c4be5a53a0b69146cb5514cca9da27385dffb96b585eadb5759d8051270f47d81c7661da216a19f18d5e7b734bc440267', 'hex'))

  sodium.crypto_stream_chacha20_xor_ic(out, out, nonce, 0, key)
  t.alike(out, Buffer.from('42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242', 'hex'))

  sodium.crypto_stream_chacha20_xor_ic(out, out, nonce, 1, key)
  t.alike(out, Buffer.from('7a42c9d864fe77d65c6606553ec89c24cb9cd7640bc49b1acbb922aa046b8bffd818895e835afc147cfbf1e6e630ba6c4be5a53a0b69146cb5514cca9da27385dffb96b585eadb5759d8051270f47d81c7661da216a19f18d5e7b734bc440267918c466e1428f08745f37a99c77c7f2b1b244bd4162e8b86e4a8bf85358202954ced04b52fef7b3ba787744e715554285ecb0ed6e133c528d69d346abc0ce8b0', 'hex'))
})

test('crypto_stream_chacha20', function (t) {
  const buf = Buffer.alloc(50)
  const nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  sodium.crypto_stream_chacha20(buf, nonce, key)

  t.unlike(buf, Buffer.alloc(50), 'contains noise now')
  const copy = Buffer.from(buf.toString('hex'), 'hex')

  sodium.crypto_stream_chacha20(buf, nonce, key)
  t.alike(buf, copy, 'predictable from nonce, key')

  t.end()
})

test('crypto_stream_chacha20_xor state', function (t) {
  const message = Buffer.from('Hello, world!')
  const nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)
  sodium.crypto_stream_chacha20_xor_init(state, nonce, key)

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_chacha20_xor_update(state, out.subarray(i, i + 1), message.subarray(i, i + 1))
  }

  sodium.crypto_stream_chacha20_xor_final(state)
  sodium.crypto_stream_chacha20_xor(out, out, nonce, key)
  t.alike(out, message, 'decrypted')
})

test('crypto_stream_chacha20_xor state with empty buffers', function (t) {
  const message = Buffer.from('Hello, world!')
  const nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)
  sodium.crypto_stream_chacha20_xor_init(state, nonce, key)

  sodium.crypto_stream_chacha20_xor_update(state, Buffer.alloc(0), Buffer.alloc(0))

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_chacha20_xor_update(state, out.subarray(i, i + 1), message.subarray(i, i + 1))
    sodium.crypto_stream_chacha20_xor_update(state, Buffer.alloc(0), Buffer.alloc(0))
  }

  sodium.crypto_stream_chacha20_xor_final(state)
  sodium.crypto_stream_chacha20_xor(out, out, nonce, key)
  t.alike(out, message, 'decrypted')
})

test('crypto_stream_chacha20_xor state long stream', function (t) {
  const nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)

  sodium.crypto_stream_chacha20_xor_init(encState, nonce, key)
  sodium.crypto_stream_chacha20_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 1000; i++) {
    const next = random(61)
    plain.push(next)

    const enc = Buffer.alloc(61)
    sodium.crypto_stream_chacha20_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(61)
    sodium.crypto_stream_chacha20_xor_update(decState, dec, enc)
    decrypted.push(dec)
  }

  const enc2 = Buffer.alloc(1000 * 61)
  sodium.crypto_stream_chacha20_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_chacha20_xor state long stream (random chunks)', function (t) {
  const nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)

  sodium.crypto_stream_chacha20_xor_init(encState, nonce, key)
  sodium.crypto_stream_chacha20_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 10000; i++) {
    const len = Math.floor(Math.random() * 256)
    const next = random(len)
    plain.push(next)

    const enc = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_xor_update(decState, dec, enc)
    decrypted.push(dec)
  }

  const enc2 = Buffer.alloc(Buffer.concat(plain).length)
  sodium.crypto_stream_chacha20_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_chacha20_xor state long stream (random chunks) with empty buffers', function (t) {
  const nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)

  sodium.crypto_stream_chacha20_xor_init(encState, nonce, key)
  sodium.crypto_stream_chacha20_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 10000; i++) {
    const len = Math.floor(Math.random() * 256)
    const next = random(len)
    plain.push(next)

    sodium.crypto_stream_chacha20_xor_update(encState, Buffer.alloc(0), Buffer.alloc(0))

    const enc = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_xor_update(decState, dec, enc)
    decrypted.push(dec)
    sodium.crypto_stream_chacha20_xor_update(decState, Buffer.alloc(0), Buffer.alloc(0))
  }

  const enc2 = Buffer.alloc(Buffer.concat(plain).length)
  sodium.crypto_stream_chacha20_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_chacha20_xor state after GC', { skip: isBare }, function (t) {
  const message = Buffer.from('Hello, world!')
  let nonce = random(sodium.crypto_stream_chacha20_NONCEBYTES)
  let key = random(sodium.crypto_stream_chacha20_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_chacha20_xor_STATEBYTES)
  sodium.crypto_stream_chacha20_xor_init(state, nonce, key)

  const nonceCopy = Buffer.from(nonce.toString('hex'), 'hex')
  const keyCopy = Buffer.from(key.toString('hex'), 'hex')
  nonce = null
  key = null

  forceGC()

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_chacha20_xor_update(state, out.subarray(i, i + 1), message.subarray(i, i + 1))
  }

  sodium.crypto_stream_chacha20_xor_final(state)
  sodium.crypto_stream_chacha20_xor(out, out, nonceCopy, keyCopy)
  t.alike(out, message, 'decrypted')
})

function random (n) {
  const buf = Buffer.alloc(n)
  sodium.randombytes_buf(buf)
  return buf
}

function forceGC () {
  require('v8').setFlagsFromString('--expose-gc')
  require('vm').runInNewContext('gc')()
}
