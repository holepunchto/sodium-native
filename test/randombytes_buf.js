var tape = require('tape')
var sodium = require('../')
var alloc = require('buffer-alloc')

tape('randombytes_buf', function (t) {
  var buf = null

  buf = alloc(10)
  sodium.randombytes_buf(buf)
  t.notEqual(buf, alloc(10), 'not blank')

  buf = alloc(1024)
  sodium.randombytes_buf(buf)
  t.notEqual(buf, alloc(1024), 'large not blank')

  t.end()
})
