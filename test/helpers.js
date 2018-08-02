var test = require('tape')
var sodium = require('..')

test('sodium_memcmp', function (assert) {
  var b1 = Buffer.from([0, 1, 2, 3])
  var b2 = Buffer.from([3, 2, 1, 0])

  assert.throws(_ => sodium.sodium_memcmp(), 'no args')
  assert.throws(_ => sodium.sodium_memcmp(b1), 'arg mismatch')
  assert.throws(_ => sodium.sodium_memcmp(b1, b2.slice(1)), 'length mismatch')
  assert.ok(sodium.sodium_memcmp(Buffer.alloc(0), Buffer.alloc(0)))
  assert.ok(sodium.sodium_memcmp(Buffer.alloc(5), Buffer.alloc(5)))
  assert.ok(sodium.sodium_memcmp(b1, b1))
  assert.notOk(sodium.sodium_memcmp(b2, b1))
  assert.notOk(sodium.sodium_memcmp(b1, b2))
  assert.end()
})

test('sodium_compare', function (assert) {
  var one = Buffer.from([1])
  var two = Buffer.from([2])
  var three = Buffer.from([3])

  assert.equal(sodium.sodium_compare(Buffer.alloc(0), Buffer.alloc(0)), 0)
  assert.equal(sodium.sodium_compare(one, one), 0)
  assert.equal(sodium.sodium_compare(two, two), 0)
  assert.equal(sodium.sodium_compare(three, three), 0)

  assert.equal(sodium.sodium_compare(one, two), -1)
  assert.equal(sodium.sodium_compare(one, three), -1)
  assert.equal(sodium.sodium_compare(two, one), 1)
  assert.equal(sodium.sodium_compare(three, one), 1)

  assert.equal(sodium.sodium_compare(two, three), -1)
  assert.equal(sodium.sodium_compare(three, two), 1)

  assert.end()
})

test('sodium_add', function (assert) {
  var large = Buffer.alloc(32)
  large[23] = 0b00000011
  var largeLessOne = Buffer.alloc(32)
  largeLessOne[23] = 0b00000001

  var c = Buffer.from(large)

  sodium.sodium_add(c, largeLessOne)
  assert.ok(large[23], 4)

  var overflow = Buffer.alloc(56, 0xff)
  var one = Buffer.alloc(56)
  one[0] = 1
  sodium.sodium_add(overflow, one)

  assert.ok(sodium.sodium_is_zero(overflow))
  assert.end()
})

test('sodium_increment', function (assert) {
  var zero = Buffer.alloc(4)
  sodium.sodium_increment(zero)

  assert.ok(zero[0], 1)

  var overflow = Buffer.alloc(56, 0xff)
  sodium.sodium_increment(overflow)

  assert.ok(sodium.sodium_is_zero(overflow))
  assert.end()
})

test('sodium_is_zero', function (assert) {
  var buf = Buffer.from([0, 0, 0, 1])

  assert.throws(_ => sodium.sodium_is_zero(), 'no args')
  assert.throws(_ => sodium.sodium_is_zero(null), 'missing buf')

  assert.ok(sodium.sodium_is_zero(Buffer.alloc(0)), 'empty buffer')
  assert.ok(sodium.sodium_is_zero(buf.subarray(0, 0)), 'zero bytes')
  assert.ok(sodium.sodium_is_zero(buf.subarray(0, 1)), 'one byte')
  assert.ok(sodium.sodium_is_zero(buf.subarray(0, 2)), 'two bytes')
  assert.ok(sodium.sodium_is_zero(buf.subarray(0, 3)), '3 bytes')
  assert.notOk(sodium.sodium_is_zero(buf), 'first non-zero byte')
  assert.ok(sodium.sodium_is_zero(buf.subarray(1, 2)), 'view')
  assert.ok(sodium.sodium_is_zero(buf.subarray(1, 2)), 'view')
  assert.notOk(sodium.sodium_is_zero(buf.subarray(3)), 'view')
  assert.end()
})
