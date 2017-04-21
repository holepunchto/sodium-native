var tape = require('tape')
var alloc = require('buffer-alloc')
var fill = require('buffer-fill')
var sodium = require('../')

tape('crypto_pwhash', function (t) {
  var output = alloc(32) // can be any size
  var passwd = new Buffer('Hej, Verden!')
  var salt = alloc(sodium.crypto_pwhash_SALTBYTES)
  var opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  var algo = sodium.crypto_pwhash_ALG_DEFAULT

  fill(salt, 'lo')

  sodium.crypto_pwhash(output, passwd, salt, opslimit, memlimit, algo)

  t.same(output.toString('hex'), '9dc3499e37e8177f5e5abdf0fa18bfb7b768970a5fd870e3c28af7a79d75c3c2', 'hashes password')

  salt[0] = 0
  sodium.crypto_pwhash(output, passwd, salt, opslimit, memlimit, algo)

  t.same(output.toString('hex'), '0170a897e8952582fa29f7cdd58e791ddabf3f32ce0268fe9bd244bccee812a8', 'diff salt -> diff hash')

  t.end()
})

tape('crypto_pwhash_str', function (t) {
  var output = alloc(sodium.crypto_pwhash_STRBYTES)
  var passwd = new Buffer('Hej, Verden!')
  var opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

  t.throws(function () {
    sodium.crypto_pwhash_str(output, passwd)
  }, 'should throw on missing args')

  sodium.crypto_pwhash_str(output, passwd, opslimit, memlimit)

  t.notEqual(output, alloc(output.length), 'not blank')
  t.notOk(sodium.crypto_pwhash_str_verify(alloc(output.length), passwd), 'does not verify')
  t.ok(sodium.crypto_pwhash_str_verify(output, passwd), 'verifies')

  t.end()
})

tape('crypto_pwhash_async', function (t) {
  var output = alloc(32) // can be any size
  var passwd = new Buffer('Hej, Verden!')
  var salt = alloc(sodium.crypto_pwhash_SALTBYTES)
  var opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  var algo = sodium.crypto_pwhash_ALG_DEFAULT

  fill(salt, 'lo')

  sodium.crypto_pwhash_async(output, passwd, salt, opslimit, memlimit, algo, function (err) {
    t.error(err)

    t.same(output.toString('hex'), '9dc3499e37e8177f5e5abdf0fa18bfb7b768970a5fd870e3c28af7a79d75c3c2', 'hashes password')

    salt[0] = 0
    sodium.crypto_pwhash_async(output, passwd, salt, opslimit, memlimit, algo, function (err) {
      t.error(err)

      t.same(output.toString('hex'), '0170a897e8952582fa29f7cdd58e791ddabf3f32ce0268fe9bd244bccee812a8', 'diff salt -> diff hash')

      t.end()
    })
  })
})

tape('crypto_pwhash_str_async', function (t) {
  var output = alloc(sodium.crypto_pwhash_STRBYTES)
  var passwd = new Buffer('Hej, Verden!')
  var opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

  t.throws(function () {
    sodium.crypto_pwhash_str_async(output, passwd)
  }, 'should throw on missing args')

  sodium.crypto_pwhash_str_async(output, passwd, opslimit, memlimit, function (err) {
    t.error(err)
    t.notEqual(output, alloc(output.length), 'not blank')
    sodium.crypto_pwhash_str_verify_async(alloc(output.length), passwd, function (err, bool) {
      t.error(err)
      console.log(bool)
      t.ok(bool === false, 'does not verify')

      sodium.crypto_pwhash_str_verify_async(output, passwd, function (err, bool) {
        t.error(err)
        t.ok(bool === true, 'verifies')
        t.end()
      })
    })
  })
})
