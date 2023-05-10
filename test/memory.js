const test = require('brittle')
const sodium = require('..')
const fork = require('child_process').fork

test('sodium_mprotect_noaccess', function (t) {
  t.plan(1)
  const p = fork(require.resolve('./fixtures/mprotect_noaccess'))

  p.on('message', function () {
    t.fail()
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})

test('sodium_mprotect_readonly', function (t) {
  t.plan(2)
  const p = fork(require.resolve('./fixtures/mprotect_readonly'))

  p.on('message', function (msg) {
    t.ok(msg === 'read')
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})

test('sodium_mprotect_readwrite', function (t) {
  t.plan(4)
  const p = fork(require.resolve('./fixtures/mprotect_readwrite'))

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

test('sodium_memzero', function (t) {
  const buf = Buffer.alloc(10, 0xab)
  const exp = Buffer.alloc(10, 0xab)
  const zero = Buffer.alloc(10)

  t.alike(buf, exp, 'buffers start out with same content')
  t.unlike(buf, zero, 'buffer is not zero')

  sodium.sodium_memzero(buf)
  t.unlike(buf, exp, 'buffers are not longer the same')
  t.alike(buf, zero, 'buffer is now zeroed')
})

test('sodium_mlock / sodium_munlock', function (t) {
  const buf = Buffer.alloc(10, 0x18)
  const exp = Buffer.alloc(10, 0x18)

  sodium.sodium_mlock(buf)
  t.absent(buf.secure)
  t.alike(buf, exp, 'mlock did not corrupt data')
  sodium.sodium_munlock(buf)
  t.absent(buf.secure)
  t.alike(buf, Buffer.alloc(10), 'munlock did zero data')
})

test('sodium_malloc', function (t) {
  const empty = sodium.sodium_malloc(0)
  const small = sodium.sodium_malloc(1)
  const large = sodium.sodium_malloc(1e8)

  t.ok(empty.secure)
  t.ok(small.secure)
  t.ok(large.secure)

  t.ok(empty.length === 0, 'has correct size')
  t.ok(small.length === 1, 'has correct size')
  t.ok(large.length === 1e8, 'has correct size')

  const expected = Buffer.from([0xdb])
  expected.secure = true
  t.alike(small, expected, 'has canary content')

  // test gc
  for (let i = 0; i < 1e3; i++) {
    if (sodium.sodium_malloc(256).length !== 256) {
      t.fail('allocated incorrect size')
    }
  }
  t.ok(empty.length === 0, 'retained correct size')
  t.ok(small.length === 1, 'retained correct size')
  t.ok(large.length === 1e8, 'retained correct size')
})

test('sodium_free', function (t) {
  if (process.version.startsWith('v10')) {
    t.comment('Skipping free test on v10')
    return
  }
  const buf = sodium.sodium_malloc(1)
  t.ok(buf.byteLength === 1)
  sodium.sodium_free(buf)
  t.ok(buf.byteLength === 0)
})

test.skip('sodium_malloc bounds', function (t) {
  t.throws(function () {
    sodium.sodium_malloc(-1)
  }, 'too small')
  t.throws(function () {
    sodium.sodium_malloc(Number.MAX_SAFE_INTEGER)
  }, 'too large')
})
