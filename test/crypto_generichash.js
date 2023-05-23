const test = require('brittle')
const sodium = require('..')

test('crypto_generichash', function (t) {
  const buf = Buffer.from('Hello, World!')

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(out, buf)

  t.alike(out.toString('hex'), '511bc81dde11180838c562c82bb35f3223f46061ebde4a955c27b3f489cf1e03', 'hashed buffer')

  const min = Buffer.alloc(sodium.crypto_generichash_BYTES_MIN)
  sodium.crypto_generichash(min, buf)

  t.alike(min.toString('hex'), '3895c59e4aeb0903396b5be3fbec69fe', 'hashed buffer min')

  const max = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
  sodium.crypto_generichash(max, buf)

  const res = '7dfdb888af71eae0e6a6b751e8e3413d767ef4fa52a7993daa9ef097f7aa3d949199c113caa37c94f80cf3b22f7d9d6e4f5def4ff927830cffe4857c34be3d89'
  t.alike(max.toString('hex'), res, 'hashed buffer max')
})

test('crypto_generichash with key', function (t) {
  const buf = Buffer.from('Hello, World!')
  const key = Buffer.alloc(sodium.crypto_generichash_KEYBYTES)

  key.fill('lo')

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(out, buf, key)

  t.alike(out.toString('hex'), 'f4113fe33d43c24c54627d40efa1a78838d4a6d689fd6e83c213848904fffa8c', 'hashed buffer')

  const min = Buffer.alloc(sodium.crypto_generichash_BYTES_MIN)
  sodium.crypto_generichash(min, buf, key)

  t.alike(min.toString('hex'), 'c8226257b0d1c3dcf4bbc3ef79574689', 'hashed buffer min')

  const max = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
  sodium.crypto_generichash(max, buf, key)

  const res = '763eda46f4c6c61abb4310eb8a488950e9e0667b2fca03c463dc7489e94f065b7af6063fe86b0441c3eb9052800121d55730412abb2cbe0761b1d66f9b047c1c'
  t.alike(max.toString('hex'), res, 'hashed buffer max')
})

test('crypto_generichash_state', function (t) {
  const state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, null, sodium.crypto_generichash_BYTES)

  const buf = Buffer.from('Hej, Verden')

  for (let i = 0; i < 10; i++) sodium.crypto_generichash_update(state, buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash_final(state, out)

  t.alike(out.toString('hex'), 'cbc20f347f5dfe37dc13231cbf7eaa4ec48e585ec055a96839b213f62bd8ce00', 'streaming hash')
})

test('crypto_generichash state with key', function (t) {
  const key = Buffer.alloc(sodium.crypto_generichash_KEYBYTES)
  key.fill('lo')

  const state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, key, sodium.crypto_generichash_BYTES)

  const buf = Buffer.from('Hej, Verden')

  for (let i = 0; i < 10; i++) sodium.crypto_generichash_update(state, buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash_final(state, out)

  t.alike(out.toString('hex'), '405f14acbeeb30396b8030f78e6a84bab0acf08cb1376aa200a500f669f675dc', 'streaming keyed hash')
})

test('crypto_generichash state with hash length', function (t) {
  const state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, null, sodium.crypto_generichash_BYTES_MIN)

  const buf = Buffer.from('Hej, Verden')

  for (let i = 0; i < 10; i++) sodium.crypto_generichash_update(state, buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES_MIN)
  sodium.crypto_generichash_final(state, out)

  t.alike(out.toString('hex'), 'decacdcc3c61948c79d9f8dee5b6aa99', 'streaming short hash')
})

test('crypto_generichash state with key and hash length', function (t) {
  const key = Buffer.alloc(sodium.crypto_generichash_KEYBYTES)
  key.fill('lo')

  const state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, key, sodium.crypto_generichash_BYTES_MIN)

  const buf = Buffer.from('Hej, Verden')

  for (let i = 0; i < 10; i++) sodium.crypto_generichash_update(state, buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES_MIN)
  sodium.crypto_generichash_final(state, out)

  t.alike(out.toString('hex'), 'fb43f0ab6872cbfd39ec4f8a1bc6fb37', 'streaming short keyed hash')
})

test('crypto_generichash_batch', function (t) {
  const buf = Buffer.from('Hej, Verden')
  const batch = []
  for (let i = 0; i < 10; i++) batch.push(buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash_batch(out, batch)

  t.alike(out.toString('hex'), 'cbc20f347f5dfe37dc13231cbf7eaa4ec48e585ec055a96839b213f62bd8ce00', 'batch hash')
})

test('crypto_generichash_batch with key', function (t) {
  const key = Buffer.alloc(sodium.crypto_generichash_KEYBYTES)
  key.fill('lo')

  const buf = Buffer.from('Hej, Verden')
  const batch = []
  for (let i = 0; i < 10; i++) batch.push(buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash_batch(out, batch, key)

  t.alike(out.toString('hex'), '405f14acbeeb30396b8030f78e6a84bab0acf08cb1376aa200a500f669f675dc', 'batch keyed hash')
})
