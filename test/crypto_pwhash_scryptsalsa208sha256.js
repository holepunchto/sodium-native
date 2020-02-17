var tape = require('tape')
var sodium = require('../')

tape('constants', function (t) {
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_BYTES_MIN != null, 'crypto_pwhash_scryptsalsa208sha256_BYTES_MIN is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_BYTES_MAX != null, 'crypto_pwhash_scryptsalsa208sha256_BYTES_MAX is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN != null, 'crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX != null, 'crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES != null, 'crypto_pwhash_scryptsalsa208sha256_SALTBYTES is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES != null, 'crypto_pwhash_scryptsalsa208sha256_STRBYTES is defined')

  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN != null, 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX != null, 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN != null, 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX != null, 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE != null, 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE != null, 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE != null, 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE is defined')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE != null, 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE is defined')
  t.end()
})

tape('crypto_pwhash_scryptsalsa208sha256', function (t) {
  var output = Buffer.alloc(32) // can be any size
  var passwd = Buffer.from('Hej, Verden!')
  var salt = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 'lo')
  var opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  sodium.crypto_pwhash_scryptsalsa208sha256(output, passwd, salt, opslimit, memlimit)

  t.same(output.toString('hex'), 'c9d280362d495e494672e44a91b94b35bb295f62c823845dd19773ded5877c2b', 'hashes password')

  salt[0] = 0
  sodium.crypto_pwhash_scryptsalsa208sha256(output, passwd, salt, opslimit, memlimit)

  t.same(output.toString('hex'), '3831bd383708c7aff661ab4f990b116c7287bafde9abd02db3174631c97042e6', 'diff salt -> diff hash')

  t.end()
})

tape('crypto_pwhash_scryptsalsa208sha256_str', function (t) {
  var output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var passwd = Buffer.from('Hej, Verden!')
  var opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  t.throws(function () {
    sodium.crypto_pwhash_scryptsalsa208sha256_str(output, passwd)
  }, 'should throw on missing args')

  sodium.crypto_pwhash_scryptsalsa208sha256_str(output, passwd, opslimit, memlimit)

  t.notEqual(output, Buffer.alloc(output.length), 'not blank')
  t.notOk(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(Buffer.alloc(output.length), passwd), 'does not verify')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(output, passwd), 'verifies')

  t.end()
})

tape('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash', function (t) {
  var passwd = Buffer.from('secret')
  var weakMem = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var weakOps = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var malformed = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var good = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var weakAlg = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  weakAlg.set('argon2i$p=2,v=19,m=1024$SGVsbG8=$SGVsbG8gd29ybA==')

  sodium.crypto_pwhash_scryptsalsa208sha256_str(weakMem, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE)
  sodium.crypto_pwhash_scryptsalsa208sha256_str(weakOps, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)
  sodium.crypto_pwhash_scryptsalsa208sha256_str(malformed, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)
  sodium.crypto_pwhash_scryptsalsa208sha256_str(good, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)

  var first$ = malformed.indexOf('$')
  var second$ = malformed.indexOf('$', first$ + 1)
  malformed.fill('p=,m=,', first$, second$, 'ascii')

  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(weakMem, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(weakOps, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(weakAlg, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.notOk(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(good, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(malformed, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))

  t.end()
})

tape('crypto_pwhash_scryptsalsa208sha256_async', function (t) {
  var output = Buffer.alloc(32) // can be any size
  var passwd = Buffer.from('Hej, Verden!')
  var salt = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 'lo')
  var opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit, function (err) {
    t.error(err)

    t.same(output.toString('hex'), 'c9d280362d495e494672e44a91b94b35bb295f62c823845dd19773ded5877c2b', 'hashes password')

    salt[0] = 0
    sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit, function (err) {
      t.error(err)

      t.same(output.toString('hex'), '3831bd383708c7aff661ab4f990b116c7287bafde9abd02db3174631c97042e6', 'diff salt -> diff hash')

      t.end()
    })
  })
})

tape('crypto_pwhash_scryptsalsa208sha256_str_async', function (t) {
  var output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var passwd = Buffer.from('Hej, Verden!')
  var opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  t.throws(function () {
    sodium.crypto_pwhash_scryptsalsa208sha256_str_async(output, passwd)
  }, 'should throw on missing args')

  sodium.crypto_pwhash_scryptsalsa208sha256_str_async(output, passwd, opslimit, memlimit, function (err) {
    t.error(err)
    t.notEqual(output, Buffer.alloc(output.length), 'not blank')
    sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(Buffer.alloc(output.length), passwd, function (err, bool) {
      t.error(err)
      t.ok(bool === false, 'does not verify')

      sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(output, passwd, function (err, bool) {
        t.error(err)
        t.ok(bool === true, 'verifies')
        t.end()
      })
    })
  })
})

tape.skip('crypto_pwhash_scryptsalsa208sha256 limits', function (t) {
  var output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  var passwd = Buffer.from('Hej, Verden!')
  var opslimit = Number.MAX_SAFE_INTEGER
  var memlimit = Number.MAX_SAFE_INTEGER

  t.throws(function () {
    sodium.crypto_pwhash_scryptsalsa208sha256_str(output, passwd, opslimit, memlimit)
  }, 'should throw on large limits')
  t.end()
})
