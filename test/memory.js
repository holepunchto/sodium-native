var alloc = require('buffer-alloc')
var tape = require('tape')
var sodium = require('../')
var fork = require('child_process').fork

tape('memzero', function (t) {
  var buf = alloc(10)
  var exp = alloc(10)
  var zero = alloc(10)
  buf.fill(0xab)
  exp.fill(0xab)

  t.same(buf, exp, 'buffers start out with same content')
  t.notSame(buf, zero, 'buffer is not zero')

  sodium.memzero(buf)
  t.notSame(buf, exp, 'buffers are not longer the same')
  t.same(buf, zero, 'buffer is now zeroed')

  t.end()
})

tape('mlock / munlock', function (t) {
  var buf = alloc(10)
  var exp = alloc(10)

  buf.fill(0x18)
  exp.fill(0x18)
  sodium.mlock(buf)
  t.same(buf, exp, 'mlock did not corrupt data')
  sodium.munlock(buf)
  t.same(buf, alloc(10), 'munlock did zero data')

  t.end()
})

tape('malloc', function (t) {
  var empty = sodium.malloc(0)
  var small = sodium.malloc(1)
  var large = sodium.malloc(1e8)

  t.ok(empty.length === 0, 'has correct size')
  t.ok(small.length === 1, 'has correct size')
  t.same(small, Buffer([0xdb]), 'has canary content')
  t.ok(large.length === 1e8, 'has correct size')

  // test gc
  for (var i = 0; i < 1e3; i++) {
    if (sodium.malloc(256).length !== 256) {
      t.fail('allocated incorrect size')
    }
  }
  t.ok(empty.length === 0, 'retained correct size')
  t.ok(small.length === 1, 'retained correct size')
  t.ok(large.length === 1e8, 'retained correct size')

  t.end()
})

tape('malloc bounds', function (t) {
  t.throws(function () {
    sodium.malloc(-1)
  }, 'too small')
  t.throws(function () {
    sodium.malloc(Number.MAX_SAFE_INTEGER)
  }, 'too large')
  t.end()
})

tape('mprotect_noaccess', function (t) {
  t.plan(1)
  var p = fork(require.resolve('./fixtures/mprotect_noaccess'))

  p.on('message', function () {
    t.fail()
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})

tape('mprotect_readonly', function (t) {
  t.plan(2)
  var p = fork(require.resolve('./fixtures/mprotect_readonly'))

  p.on('message', function (msg) {
    t.ok(msg === 'read')
  })
  p.on('exit', function (code, signal) {
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})

tape('mprotect_readwrite', function (t) {
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
    t.ok(p.signalCode !== null || p.exitCode > 0)
  })
})
