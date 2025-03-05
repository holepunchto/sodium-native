const test = require('brittle')
const sodium = require('..')
const { isBare } = require('which-runtime')

const tests = [
  ['0000000000000000000000000000000000000000000000000000000000000000', '000000000000000000000000', 0, '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d'],
  ['0000000000000000000000000000000000000000000000000000000000000000', '000000000000000000000000', 1, '9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d012737681f7b5d0f281e3afde458bc1e73d2d313c9cf94c05ff3716240a248f21320a058d7b3566bd520daaa3ed2bf0ac5b8b120fb852773c3639734b45c91a4'],
  ['0000000000000000000000000000000000000000000000000000000000000001', '000000000000000000000000', 1, '3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a096d68b9ff7b57e7090f880392effd5b297a83bbaf2fbe8cf5d4618965e3dc776cd430d9b4e7eda8a767fb0e860319aadb5fd96a855de1fbfc92cb0489190cfdd87da6dbf1f736a2d499941ca097e5170bd685578611323120cebf296181ed4f5'],
  ['00ff000000000000000000000000000000000000000000000000000000000000', '000000000000000000000000', 2, '72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096bf74dbd52cc4fc95ceb6097fe5e65358c9dbc0a5ecbf7894a132a9a54ae3e951f2e9f209aa9c3d9a877ac9dab62433d2961a17d103e455dfb7337c90f6857aad233065955a212b5c7a8eab4dc8a629e5b6b8ba914afd06de7177054b33d21c96'],
  ['0000000000000000000000000000000000000000000000000000000000000000', '000000000000000000000002', 0, 'c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d1a91288c874ec254f322c2a197340c55bb3e9b3998f7de2309486a0bb494abd20c9c5ef99c1370d61e77f408ac5514f49202bcc6828d45409d2d1416f8ae106b06ebd2541256264fa415bd54cb12e1d4449ed85299a1b7a249b75ff6c89b2e3f'],
  ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '000000090000004a00000000', 1, '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e0a88837739d7bf4ef8ccacb0ea2bb9d69d56c394aa351dfda5bf459f0a2e9fe8e721f89255f9c486bf21679c683d4f9c5cf2fa27865526005b06ca374c86af3bdcbfbdcb83be65862ed5c20eae5a43241d6a92da6dca9a156be25297f51c2718'],
  ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '000000090000004a00000000', 0xfeffffff, '75924bad7831b25662dbac54b46827990b6168ae990e7bd7e1fd2ad282bf23ef052c7d1a0a6c1ef862070943a0d4da24705fbc006dfb85e2af18c0a264d772a44c70fbedac9d6a6867ff6be0a32826507f2c784101583211c9e2453d4cc8b283d5e86682bd4bf511271b91dbd351415f5a009d1f78b64085a9a4341be7d42e2679d57e2747097f0129950e2c9e9ca1356022d45da252af71ac37f351a2e77911']
]

const vectors = [
  '8a010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
  '8adc91fd040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404',
  '8adc91fd9ff4f0070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707',
  '8adc91fd9ff4f0f51b0f0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a',
  '8adc91fd9ff4f0f51b0fad50ff0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d',
  '8adc91fd9ff4f0f51b0fad50ff15d637101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efd131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919191919',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a742001c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c151f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd98222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d5282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f492e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69c313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1f343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a755843a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d693d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d',
  '8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d690a35d4404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040'
]

test('constants', function (t) {
  t.ok(sodium.crypto_stream_chacha20_ietf_KEYBYTES > 0)
  t.ok(sodium.crypto_stream_chacha20_ietf_NONCEBYTES > 0)
  t.ok(sodium.crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX > 0)
})

test('libsodium crypto_stream_chacha20_ietf', function (t) {
  const key = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_KEYBYTES)
  const nonce = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)

  const out = Buffer.alloc(160)

  for (let i = 0; i < tests.length; i++) {
    key.write(tests[i][0], 0, key.byteLength, 'hex')
    nonce.write(tests[i][1], 0, nonce.byteLength, 'hex')
    out.fill(0)
    sodium.crypto_stream_chacha20_ietf_xor_ic(out, out, nonce, tests[i][2], key)
    t.alike(out, Buffer.from(tests[i][3], 'hex'), 'crypto_stream_chacha20_ietf_xor_ic vector ' + i)
    for (let plen = 0; plen < out.byteLength; plen++) {
      const part = Buffer.alloc(plen)
      sodium.crypto_stream_chacha20_ietf_xor_ic(part, out.subarray(0, plen), nonce, tests[i][2], key)
      if (part.every(b => b === 0) === false) return t.fail()
    }
  }

  for (let plen = 1, i = 0; plen < 66; plen += 3, i++) {
    out.fill(plen & 0xff)
    sodium.crypto_stream_chacha20_ietf(out.subarray(0, plen), nonce, key)
    if (out.equals(Buffer.from(vectors[i], 'hex')) === false) return t.fail()
  }

  sodium.randombytes_buf(out)
  sodium.crypto_stream_chacha20_ietf(out, nonce, key)
  t.alike(out, Buffer.from('8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d690a35d410f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e0a88837739d7bf4ef8ccacb0ea2bb9d69d56c394aa351dfda5bf459f0a2e9fe8', 'hex'))

  t.execution(() => sodium.crypto_stream_chacha20_ietf(out.subarray(0, 0), nonce, key))
  t.execution(() => sodium.crypto_stream_chacha20_ietf_xor(out.subarray(0, 0), Buffer.alloc(0), nonce, key))
  t.execution(() => sodium.crypto_stream_chacha20_ietf_xor(out.subarray(0, 0), Buffer.alloc(0), nonce, key))
  t.execution(() => sodium.crypto_stream_chacha20_ietf_xor_ic(out.subarray(0, 0), Buffer.alloc(0), nonce, 1, key))

  out.fill(0x42)
  sodium.crypto_stream_chacha20_ietf_xor(out, out, nonce, key)
  t.alike(out, Buffer.from('c89ed3bfddb6b2b7594def12bd579475a64cbfe0448e1085c1e50042127e57c08fda71743f4816973f7edcdbcd0b4ca4dee10e5dbbab7be517c6876f2b48779652b3a5a693791b57124d9f5de16233868593b68571822a414660e8d881962e0c90c0260445dde84b568095479bc940e0f750de939c540cfb8992c1aae0127e0c48cac1357b95fd0cba8eeef2a869fb94df1481d6e8775fbfe7fd07dd486cddaa', 'hex'))

  sodium.crypto_stream_chacha20_ietf_xor_ic(out, out, nonce, 0, key)
  t.alike(out, Buffer.from('42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242', 'hex'))

  sodium.crypto_stream_chacha20_ietf_xor_ic(out, out, nonce, 1, key)
  t.alike(out, Buffer.from('52b3a5a693791b57124d9f5de16233868593b68571822a414660e8d881962e0c90c0260445dde84b568095479bc940e0f750de939c540cfb8992c1aae0127e0c48cac1357b95fd0cba8eeef2a869fb94df1481d6e8775fbfe7fd07dd486cddaaa563bad017bb86c4fd6325de2a7f0dde1eb0b865c4176442194488750ec4ed799efdff89c1fc27c46c97804cec1801665f28d0982f88d85729a010d5b75e655a', 'hex'))
})

test('crypto_stream_chacha20_ietf', function (t) {
  const buf = Buffer.alloc(50)
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  sodium.crypto_stream_chacha20_ietf(buf, nonce, key)

  t.unlike(buf, Buffer.alloc(50), 'contains noise now')
  const copy = Buffer.from(buf.toString('hex'), 'hex')

  sodium.crypto_stream_chacha20_ietf(buf, nonce, key)
  t.alike(buf, copy, 'predictable from nonce, key')

  t.end()
})

test('crypto_stream_chacha20_ietf_xor', function (t) {
  const message = Buffer.from('Hello, World!')
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  sodium.crypto_stream_chacha20_ietf_xor(message, message, nonce, key)

  t.unlike(message, Buffer.from('Hello, World!'), 'encrypted')

  sodium.crypto_stream_chacha20_ietf_xor(message, message, nonce, key)

  t.alike(message, Buffer.from('Hello, World!'), 'decrypted')

  t.end()
})

test('crypto_stream_chacha20_ietf_xor state', function (t) {
  const message = Buffer.from('Hello, world!')
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)
  sodium.crypto_stream_chacha20_ietf_xor_init(state, nonce, key)

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_chacha20_ietf_xor_update(state, out.slice(i, i + 1), message.slice(i, i + 1))
  }

  sodium.crypto_stream_chacha20_ietf_xor_final(state)
  sodium.crypto_stream_chacha20_ietf_xor(out, out, nonce, key)
  t.alike(out, message, 'decrypted')
})

test('crypto_stream_chacha20_ietf_xor state with empty buffers', function (t) {
  const message = Buffer.from('Hello, world!')
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)
  sodium.crypto_stream_chacha20_ietf_xor_init(state, nonce, key)

  sodium.crypto_stream_chacha20_ietf_xor_update(state, Buffer.alloc(0), Buffer.alloc(0))

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_chacha20_ietf_xor_update(state, out.slice(i, i + 1), message.slice(i, i + 1))
    sodium.crypto_stream_chacha20_ietf_xor_update(state, Buffer.alloc(0), Buffer.alloc(0))
  }

  sodium.crypto_stream_chacha20_ietf_xor_final(state)
  sodium.crypto_stream_chacha20_ietf_xor(out, out, nonce, key)
  t.alike(out, message, 'decrypted')
})

test('crypto_stream_chacha20_ietf_xor state long stream', function (t) {
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)

  sodium.crypto_stream_chacha20_ietf_xor_init(encState, nonce, key)
  sodium.crypto_stream_chacha20_ietf_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 1000; i++) {
    const next = random(61)
    plain.push(next)

    const enc = Buffer.alloc(61)
    sodium.crypto_stream_chacha20_ietf_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(61)
    sodium.crypto_stream_chacha20_ietf_xor_update(decState, dec, enc)
    decrypted.push(dec)
  }

  const enc2 = Buffer.alloc(1000 * 61)
  sodium.crypto_stream_chacha20_ietf_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_chacha20_ietf_xor state long stream (random chunks)', function (t) {
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)

  sodium.crypto_stream_chacha20_ietf_xor_init(encState, nonce, key)
  sodium.crypto_stream_chacha20_ietf_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 10000; i++) {
    const len = Math.floor(Math.random() * 256)
    const next = random(len)
    plain.push(next)

    const enc = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_ietf_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_ietf_xor_update(decState, dec, enc)
    decrypted.push(dec)
  }

  const enc2 = Buffer.alloc(Buffer.concat(plain).length)
  sodium.crypto_stream_chacha20_ietf_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_chacha20_ietf_xor state long stream (random chunks) with empty buffers', function (t) {
  const nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  const key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)

  sodium.crypto_stream_chacha20_ietf_xor_init(encState, nonce, key)
  sodium.crypto_stream_chacha20_ietf_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 10000; i++) {
    const len = Math.floor(Math.random() * 256)
    const next = random(len)
    plain.push(next)

    sodium.crypto_stream_chacha20_ietf_xor_update(encState, Buffer.alloc(0), Buffer.alloc(0))

    const enc = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_ietf_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(len)
    sodium.crypto_stream_chacha20_ietf_xor_update(decState, dec, enc)
    decrypted.push(dec)
    sodium.crypto_stream_chacha20_ietf_xor_update(decState, Buffer.alloc(0), Buffer.alloc(0))
  }

  const enc2 = Buffer.alloc(Buffer.concat(plain).length)
  sodium.crypto_stream_chacha20_ietf_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_chacha20_xor state after GC', { skip: isBare }, function (t) {
  const message = Buffer.from('Hello, world!')
  let nonce = random(sodium.crypto_stream_chacha20_ietf_NONCEBYTES)
  let key = random(sodium.crypto_stream_chacha20_ietf_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_chacha20_ietf_xor_STATEBYTES)
  sodium.crypto_stream_chacha20_ietf_xor_init(state, nonce, key)

  const nonceCopy = Buffer.from(nonce.toString('hex'), 'hex')
  const keyCopy = Buffer.from(key.toString('hex'), 'hex')
  nonce = null
  key = null

  forceGC()

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_chacha20_ietf_xor_update(state, out.slice(i, i + 1), message.slice(i, i + 1))
  }

  sodium.crypto_stream_chacha20_ietf_xor_final(state)
  sodium.crypto_stream_chacha20_ietf_xor(out, out, nonceCopy, keyCopy)
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
