var test = require('tape')
var sodium = require('../')

test('constants', function (assert) {
  assert.same(typeof sodium.randombytes_SEEDBYTES, 'number', 'randombytes_SEEDBYTES is number')

  assert.end()
})

test('bad inputs', function (assert) {
  assert.throws(() => sodium.randombytes_uniform(), 'randombytes_uniform throws with no arguments')
  assert.throws(() => sodium.randombytes_buf([]), 'randombytes_buf generic array throws')
  assert.doesNotThrow(() => sodium.randombytes_buf(new Uint32Array(0)), 'randombytes_buf with new Uint32Array(0) does not throw')
  assert.end()
})

test('', function (assert) {
  const arrayBuffer = new ArrayBuffer(32)
  const buf = new Uint32Array(arrayBuffer, 8, 2)
  const viewBufStart = new Uint32Array(arrayBuffer, 0, 2)
  const viewBufEnd = new Uint32Array(arrayBuffer, 16)
  sodium.randombytes_buf(buf)

  assert.ok(viewBufStart.every(el => el === 0), 'randombytes_buf does not touch view offset start')
  assert.ok(viewBufEnd.every(el => el === 0), 'randombytes_buf does not touch view offset end')

  assert.end()
})

test('randombytes_random', function (assert) {
  for (var i = 0; i < 1e6; i++) {
    var n = sodium.randombytes_random()
    if (n > 0xffffffff || n < 0) assert.fail()
  }

  assert.end()
})

test('randombytes_uniform', function (assert) {
  var p = 5381
  for (var i = 0; i < 1e6; i++) {
    var n = sodium.randombytes_uniform(5381)
    if (n >= p || n < 0) assert.fail()
  }

  assert.end()
})

test('randombytes_buf', function (assert) {
  var buf = null

  buf = Buffer.alloc(10)
  sodium.randombytes_buf(buf)
  assert.notEqual(buf, Buffer.alloc(10), 'not blank')

  buf = Buffer.alloc(1024)
  sodium.randombytes_buf(buf)
  assert.notEqual(buf, Buffer.alloc(1024), 'large not blank')

  assert.end()
})

test.skip('randombytes_deterministic', function (assert) {
  var seed1 = Buffer.allocUnsafe(sodium.randombytes_SEEDBYTES)
  var seed2 = Buffer.allocUnsafe(sodium.randombytes_SEEDBYTES)
  var buf1 = Buffer.alloc(10)
  var buf2 = Buffer.alloc(10)

  for (var i = 0; i < 1e6; i++) {
    sodium.randombytes_buf(seed1)
    sodium.randombytes_buf(seed2)

    sodium.randombytes_buf_deterministic(buf1, seed1)
    sodium.randombytes_buf_deterministic(buf2, seed1)
    if (!buf1.equals(buf2)) assert.fail('should equal')

    sodium.randombytes_buf_deterministic(buf1, seed1)
    sodium.randombytes_buf_deterministic(buf2, seed2)
    if (buf1.equals(buf2)) assert.fail('should not equal')

    sodium.randombytes_buf_deterministic(buf1, seed2)
    sodium.randombytes_buf_deterministic(buf2, seed1)
    if (buf1.equals(buf2)) assert.fail('should not equal')

    sodium.randombytes_buf_deterministic(buf1, seed2)
    sodium.randombytes_buf_deterministic(buf2, seed2)
    if (!buf1.equals(buf2)) assert.fail('should equal')
  }

  assert.end()
})
