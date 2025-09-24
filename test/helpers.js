const test = require('brittle')
const sodium = require('..')

test('sodium_memcmp', function (t) {
  const b1 = Buffer.from([0, 1, 2, 3])
  const b2 = Buffer.from([3, 2, 1, 0])

  t.exception.all(_ => sodium.sodium_memcmp(b1, b2.subarray(1)), 'length mismatch')
  t.ok(sodium.sodium_memcmp(Buffer.alloc(0), Buffer.alloc(0)))
  t.ok(sodium.sodium_memcmp(Buffer.alloc(5), Buffer.alloc(5)))
  t.ok(sodium.sodium_memcmp(b1, b1))
  t.absent(sodium.sodium_memcmp(b2, b1))
  t.absent(sodium.sodium_memcmp(b1, b2))
})

test('sodium_compare', function (t) {
  const one = Buffer.from([1])
  const two = Buffer.from([2])
  const three = Buffer.from([3])

  t.is(sodium.sodium_compare(Buffer.alloc(0), Buffer.alloc(0)), 0)
  t.is(sodium.sodium_compare(one, one), 0)
  t.is(sodium.sodium_compare(two, two), 0)
  t.is(sodium.sodium_compare(three, three), 0)

  t.is(sodium.sodium_compare(one, two), -1)
  t.is(sodium.sodium_compare(one, three), -1)
  t.is(sodium.sodium_compare(two, one), 1)
  t.is(sodium.sodium_compare(three, one), 1)

  t.is(sodium.sodium_compare(two, three), -1)
  t.is(sodium.sodium_compare(three, two), 1)
})

test('sodium_add', function (t) {
  const large = Buffer.alloc(32)
  large[23] = 0b00000011
  const largeLessOne = Buffer.alloc(32)
  largeLessOne[23] = 0b00000001

  const c = Buffer.from(large)

  sodium.sodium_add(c, largeLessOne)
  t.ok(large[23], 4)

  const overflow = Buffer.alloc(56, 0xff)
  const one = Buffer.alloc(56)
  one[0] = 1
  sodium.sodium_add(overflow, one)

  t.ok(sodium.sodium_is_zero(overflow))
})

test('sub', function (t) {
  const large = Buffer.alloc(32)
  large[23] = 0b00000011
  const largeLessOne = Buffer.alloc(32)
  largeLessOne[23] = 0b00000001

  const c = Buffer.from(large)

  sodium.sodium_sub(c, largeLessOne)
  t.ok(large[23], 2)

  const overflow = Buffer.alloc(56, 0x00)
  const one = Buffer.alloc(56)
  one[0] = 1
  sodium.sodium_sub(overflow, one)

  t.ok(sodium.sodium_memcmp(overflow, Buffer.alloc(56, 0xff)))
})

test('sodium_increment', function (t) {
  const zero = Buffer.alloc(4)
  sodium.sodium_increment(zero)

  t.ok(zero[0], 1)

  const overflow = Buffer.alloc(56, 0xff)
  sodium.sodium_increment(overflow)

  t.ok(sodium.sodium_is_zero(overflow))
})

test('sodium_is_zero', function (t) {
  const buf = Buffer.from([0, 0, 0, 1])

  t.exception.all(_ => sodium.sodium_is_zero(), 'no args')
  t.exception.all(_ => sodium.sodium_is_zero(null), 'missing buf')

  t.ok(sodium.sodium_is_zero(Buffer.alloc(0)), 'empty buffer')
  t.ok(sodium.sodium_is_zero(buf.subarray(0, 0)), 'zero bytes')
  t.ok(sodium.sodium_is_zero(buf.subarray(0, 1)), 'one byte')
  t.ok(sodium.sodium_is_zero(buf.subarray(0, 2)), 'two bytes')
  t.ok(sodium.sodium_is_zero(buf.subarray(0, 3)), '3 bytes')
  t.absent(sodium.sodium_is_zero(buf), 'first non-zero byte')
  t.ok(sodium.sodium_is_zero(buf.subarray(1, 2)), 'view')
  t.ok(sodium.sodium_is_zero(buf.subarray(1, 2)), 'view')
  t.absent(sodium.sodium_is_zero(buf.subarray(3)), 'view')
})
