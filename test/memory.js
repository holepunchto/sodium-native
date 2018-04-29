var tape = require('tape')
var sodium = require('../')
var fork = require('child_process').fork

tape.only('Type support', function (t) {
  t.throws(_ => sodium.sodium_memzero([]), 'throws on array')
  t.throws(_ => sodium.sodium_memzero('str'), 'throws on string')
  t.throws(_ => sodium.sodium_memzero({}), 'throws on object')
  t.throws(_ => sodium.sodium_memzero(1 | 0), 'throws on int')
  t.throws(_ => sodium.sodium_memzero(1.1), 'throws on Number')

  var u8 = new Uint8Array(32)
  sodium.randombytes_buf(u8)
  t.ok(u8.some(b => b !== 0), 'u8 has non-zero element')
  sodium.sodium_memzero(u8)
  t.ok(u8.every(b => b === 0), 'u8 did zero out')

  var u16 = new Uint16Array(32)
  sodium.randombytes_buf(u16)
  t.ok(u16.some(b => b !== 0), 'u16 has non-zero element')
  sodium.sodium_memzero(u16)
  t.ok(u16.every(b => b === 0), 'u16 did zero out')

  var u32 = new Uint32Array(32)
  sodium.randombytes_buf(u32)
  t.ok(u32.some(b => b !== 0), 'u32 has non-zero element')
  sodium.sodium_memzero(u32)
  t.ok(u32.every(b => b === 0), 'u32 did zero out')

  var s8 = new Int8Array(32)
  sodium.randombytes_buf(s8)
  t.ok(s8.some(b => b !== 0), 's8 has non-zero element')
  sodium.sodium_memzero(s8)
  t.ok(s8.every(b => b === 0), 's8 did zero out')

  var s16 = new Int16Array(32)
  sodium.randombytes_buf(s16)
  t.ok(s16.some(b => b !== 0), 's16 has non-zero element')
  sodium.sodium_memzero(s16)
  t.ok(s16.every(b => b === 0), 's16 did zero out')

  var s32 = new Int32Array(32)
  sodium.randombytes_buf(s32)
  t.ok(s32.some(b => b !== 0), 's32 has non-zero element')
  sodium.sodium_memzero(s32)
  t.ok(s32.every(b => b === 0), 's32 did zero out')

  var float = new Float32Array(32)
  sodium.randombytes_buf(float)
  t.ok(float.some(b => b !== 0), 'float has non-zero element')
  sodium.sodium_memzero(float)
  t.ok(float.every(b => b === 0), 'float did zero out')

  var double = new Float64Array(32)
  sodium.randombytes_buf(double)
  t.ok(double.some(b => b !== 0), 'double has non-zero element')
  sodium.sodium_memzero(double)
  t.ok(double.every(b => b === 0), 'double did zero out')

  var buf = Buffer.alloc(32)
  sodium.randombytes_buf(buf)
  t.ok(buf.some(b => b !== 0), 'buf has non-zero element')
  sodium.sodium_memzero(buf)
  t.ok(buf.every(b => b === 0), 'buf did zero out')

  var sbuf = sodium.sodium_malloc(32)
  sodium.randombytes_buf(sbuf)
  t.ok(sbuf.some(b => b !== 0), 'sbuf has non-zero element')
  sodium.sodium_memzero(sbuf)
  t.ok(sbuf.every(b => b === 0), 'sbuf did zero out')

  t.end()
})

tape('sodium_memzero', function (t) {
  var buf = Buffer.alloc(10, 0xab)
  var exp = Buffer.alloc(10, 0xab)
  var zero = Buffer.alloc(10)

  t.same(buf, exp, 'buffers start out with same content')
  t.notSame(buf, zero, 'buffer is not zero')

  sodium.sodium_memzero(buf)
  t.notSame(buf, exp, 'buffers are not longer the same')
  t.same(buf, zero, 'buffer is now zeroed')

  t.end()
})

tape('sodium_mlock / sodium_munlock', function (t) {
  var buf = Buffer.alloc(10, 0x18)
  var exp = Buffer.alloc(10, 0x18)

  sodium.sodium_mlock(buf)
  t.notOk(buf.secure)
  t.same(buf, exp, 'mlock did not corrupt data')
  sodium.sodium_munlock(buf)
  t.notOk(buf.secure)
  t.same(buf, Buffer.alloc(10), 'munlock did zero data')

  t.end()
})

tape('sodium_malloc', function (t) {
  var empty = sodium.sodium_malloc(0)
  var small = sodium.sodium_malloc(1)
  var large = sodium.sodium_malloc(1e8)

  t.ok(empty.secure)
  t.ok(small.secure)
  t.ok(large.secure)

  t.ok(empty.length === 0, 'has correct size')
  t.ok(small.length === 1, 'has correct size')
  t.same(small, Buffer([0xdb]), 'has canary content')
  t.ok(large.length === 1e8, 'has correct size')

  // test gc
  for (var i = 0; i < 1e3; i++) {
    if (sodium.sodium_malloc(256).length !== 256) {
      t.fail('allocated incorrect size')
    }
  }
  t.ok(empty.length === 0, 'retained correct size')
  t.ok(small.length === 1, 'retained correct size')
  t.ok(large.length === 1e8, 'retained correct size')

  t.end()
})

tape('sodium_malloc .secure read-only', function (t) {
  var buf = sodium.sodium_malloc(1)

  t.ok(buf.secure)
  buf.secure = false
  t.ok(buf.secure)
  t.end()
})

tape('sodium_malloc bounds', function (t) {
  t.throws(function () {
    sodium.sodium_malloc(-1)
  }, 'too small')
  t.throws(function () {
    sodium.sodium_malloc(Number.MAX_SAFE_INTEGER)
  }, 'too large')
  t.end()
})

tape('sodium_mprotect_noaccess', function (t) {
  t.plan(1)
  var p = fork(require.resolve('./fixtures/mprotect_noaccess'))

  p.on('message', function () {
    t.fail()
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})

tape('sodium_mprotect_readonly', function (t) {
  t.plan(2)
  var p = fork(require.resolve('./fixtures/mprotect_readonly'))

  p.on('message', function (msg) {
    t.ok(msg === 'read')
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})

tape('sodium_mprotect_readwrite', function (t) {
  t.plan(4)
  var p = fork(require.resolve('./fixtures/mprotect_readwrite'))

  p.on('message', function (msg) {
    switch (msg) {
      case 'read': t.pass()
        break
      case 'write': t.pass()
        break
      case 'did_write': t.pass()
        break
      case 'did_not_write': t.fail()
        break
      default: t.fail()
        break
    }
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode === null || p.exitCode === 0)
  })
})
