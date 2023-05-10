const test = require('brittle')
const sodium = require('..')

test('constants', function (t) {
  t.alike(typeof sodium.randombytes_SEEDBYTES, 'number', 'randombytes_SEEDBYTES is number')
})

test('randombytes_random', function (t) {
  for (let i = 0; i < 1e6; i++) {
    const n = sodium.randombytes_random()
    if (n > 0xffffffff || n < 0) t.fail()
  }
})

test('randombytes_uniform', function (t) {
  const p = 5381
  for (let i = 0; i < 1e6; i++) {
    const n = sodium.randombytes_uniform(5381)
    if (n >= p || n < 0) t.fail()
  }
})

test('randombytes_buf', function (t) {
  let buf = null

  buf = Buffer.alloc(10)
  sodium.randombytes_buf(buf)
  t.not(buf, Buffer.alloc(10), 'not blank')

  buf = Buffer.alloc(1024)
  sodium.randombytes_buf(buf)
  t.not(buf, Buffer.alloc(1024), 'large not blank')
})

test('randombytes_deterministic', function (t) {
  const seed1 = Buffer.allocUnsafe(sodium.randombytes_SEEDBYTES)
  const seed2 = Buffer.allocUnsafe(sodium.randombytes_SEEDBYTES)
  const buf1 = Buffer.alloc(10)
  const buf2 = Buffer.alloc(10)

  for (let i = 0; i < 1e6; i++) {
    sodium.randombytes_buf(seed1)
    sodium.randombytes_buf(seed2)

    sodium.randombytes_buf_deterministic(buf1, seed1)
    sodium.randombytes_buf_deterministic(buf2, seed1)
    if (!buf1.equals(buf2)) t.fail('should equal')

    sodium.randombytes_buf_deterministic(buf1, seed1)
    sodium.randombytes_buf_deterministic(buf2, seed2)
    if (buf1.equals(buf2)) t.fail('should not equal')

    sodium.randombytes_buf_deterministic(buf1, seed2)
    sodium.randombytes_buf_deterministic(buf2, seed1)
    if (buf1.equals(buf2)) t.fail('should not equal')

    sodium.randombytes_buf_deterministic(buf1, seed2)
    sodium.randombytes_buf_deterministic(buf2, seed2)
    if (!buf1.equals(buf2)) t.fail('should equal')
  }
})
