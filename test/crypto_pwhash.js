var tape = require('tape')
var alloc = require('buffer-alloc')
var fill = require('buffer-fill')
var sodium = require('../')

tape('constants', function (t) {
  t.ok(sodium.crypto_pwhash_ALG_ARGON2I13 != null, 'crypto_pwhash_ALG_ARGON2I13 is defined')
  t.ok(sodium.crypto_pwhash_ALG_ARGON2ID13 != null, 'crypto_pwhash_ALG_ARGON2ID13 is defined')
  t.ok(sodium.crypto_pwhash_ALG_DEFAULT === sodium.crypto_pwhash_ALG_ARGON2ID13, 'crypto_pwhash_ALG_DEFAULT is crypto_pwhash_ALG_ARGON2ID13')
  t.ok(sodium.crypto_pwhash_BYTES_MIN != null, 'crypto_pwhash_BYTES_MIN is defined')
  t.ok(sodium.crypto_pwhash_BYTES_MAX != null, 'crypto_pwhash_BYTES_MAX is defined')
  t.ok(sodium.crypto_pwhash_PASSWD_MIN != null, 'crypto_pwhash_PASSWD_MIN is defined')
  t.ok(sodium.crypto_pwhash_PASSWD_MAX != null, 'crypto_pwhash_PASSWD_MAX is defined')
  t.ok(sodium.crypto_pwhash_SALTBYTES != null, 'crypto_pwhash_SALTBYTES is defined')
  t.ok(sodium.crypto_pwhash_STRBYTES != null, 'crypto_pwhash_STRBYTES is defined')

  t.ok(sodium.crypto_pwhash_OPSLIMIT_MIN != null, 'crypto_pwhash_OPSLIMIT_MIN is defined')
  t.ok(sodium.crypto_pwhash_OPSLIMIT_MAX != null, 'crypto_pwhash_OPSLIMIT_MAX is defined')
  t.ok(sodium.crypto_pwhash_MEMLIMIT_MIN != null, 'crypto_pwhash_MEMLIMIT_MIN is defined')
  t.ok(sodium.crypto_pwhash_MEMLIMIT_MAX != null, 'crypto_pwhash_MEMLIMIT_MAX is defined')
  t.ok(sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE != null, 'crypto_pwhash_OPSLIMIT_INTERACTIVE is defined')
  t.ok(sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE != null, 'crypto_pwhash_MEMLIMIT_INTERACTIVE is defined')
  t.ok(sodium.crypto_pwhash_OPSLIMIT_MODERATE != null, 'crypto_pwhash_OPSLIMIT_MODERATE is defined')
  t.ok(sodium.crypto_pwhash_MEMLIMIT_MODERATE != null, 'crypto_pwhash_MEMLIMIT_MODERATE is defined')
  t.ok(sodium.crypto_pwhash_OPSLIMIT_SENSITIVE != null, 'crypto_pwhash_OPSLIMIT_SENSITIVE is defined')
  t.ok(sodium.crypto_pwhash_MEMLIMIT_SENSITIVE != null, 'crypto_pwhash_MEMLIMIT_SENSITIVE is defined')
  t.end()
})

tape('crypto_pwhash', function (t) {
  var output = alloc(32) // can be any size
  var passwd = new Buffer('Hej, Verden!')
  var salt = alloc(sodium.crypto_pwhash_SALTBYTES)
  var opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  var algo = sodium.crypto_pwhash_ALG_DEFAULT

  fill(salt, 'lo')

  sodium.crypto_pwhash(output, passwd, salt, opslimit, memlimit, algo)

  t.same(output.toString('hex'), 'f0236e17ec70050fc989f19d8ce640301e8f912154b4f0afc1552cdf246e659f', 'hashes password')

  salt[0] = 0
  sodium.crypto_pwhash(output, passwd, salt, opslimit, memlimit, algo)

  t.same(output.toString('hex'), 'df73f15d217196311d4b1aa6fba339905ffe581dee4bd3a95ec2bb7c52991d65', 'diff salt -> diff hash')

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

  t.notSame(output, alloc(output.length), 'not blank')
  t.notOk(sodium.crypto_pwhash_str_verify(output, Buffer.from('Hello world')), 'does not verify')
  t.ok(sodium.crypto_pwhash_str_verify(output, passwd), 'verifies')

  t.end()
})

tape('crypto_pwhash_str_needs_rehash', function (t) {
  var passwd = Buffer.from('secret')
  var weakMem = alloc(sodium.crypto_pwhash_STRBYTES)
  var weakOps = alloc(sodium.crypto_pwhash_STRBYTES)
  var malformed = alloc(sodium.crypto_pwhash_STRBYTES)
  var good = alloc(sodium.crypto_pwhash_STRBYTES)
  var weakAlg = Buffer.alloc(128)
  weakAlg.set('argon2i$p=2,v=19,m=1024$SGVsbG8=$SGVsbG8gd29ybA==')

  sodium.crypto_pwhash_str(weakMem, passwd, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
  sodium.crypto_pwhash_str(weakOps, passwd, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_MODERATE)
  sodium.crypto_pwhash_str(malformed, passwd, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE)
  sodium.crypto_pwhash_str(good, passwd, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE)

  var first$ = malformed.indexOf('$')
  var second$ = malformed.indexOf('$', first$ + 1)
  malformed.fill('p=,m=,', first$, second$, 'ascii')

  t.ok(sodium.crypto_pwhash_str_needs_rehash(weakMem, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE))
  t.ok(sodium.crypto_pwhash_str_needs_rehash(weakOps, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE))
  t.ok(sodium.crypto_pwhash_str_needs_rehash(weakAlg, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE))
  t.notOk(sodium.crypto_pwhash_str_needs_rehash(good, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE))
  t.ok(sodium.crypto_pwhash_str_needs_rehash(malformed, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE))

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

    t.same(output.toString('hex'), 'f0236e17ec70050fc989f19d8ce640301e8f912154b4f0afc1552cdf246e659f', 'hashes password')

    salt[0] = 0
    sodium.crypto_pwhash_async(output, passwd, salt, opslimit, memlimit, algo, function (err) {
      t.error(err)

      t.same(output.toString('hex'), 'df73f15d217196311d4b1aa6fba339905ffe581dee4bd3a95ec2bb7c52991d65', 'diff salt -> diff hash')

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
    t.notSame(output, alloc(output.length), 'not blank')
    sodium.crypto_pwhash_str_verify_async(output, Buffer.from('hello world'), function (err, bool) {
      t.error(err)
      t.ok(bool === false, 'does not verify')

      sodium.crypto_pwhash_str_verify_async(output, passwd, function (err, bool) {
        t.error(err)
        t.ok(bool === true, 'verifies')
        t.end()
      })
    })
  })
})

tape('crypto_pwhash limits', function (t) {
  var output = alloc(sodium.crypto_pwhash_STRBYTES)
  var passwd = new Buffer('Hej, Verden!')
  var opslimit = Number.MAX_SAFE_INTEGER
  var memlimit = Number.MAX_SAFE_INTEGER

  t.throws(function () {
    sodium.crypto_pwhash_str(output, passwd, opslimit, memlimit)
  }, 'should throw on large limits')
  t.end()
})

tape('error conditions sync', function (t) {
  var password = Buffer.from('changeme2')
  var hashStr = Buffer.from('$argon2id$v=19$m=65536,t=2,p=1$49cWoO3+fsK3HOFu3cRc/g$BwhPqR5BtORXs3E0PU0S+uf9SSyRjMSr0AkA9VNM5yY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000')
  var malformedHashStr = Buffer.from('$argon2id$v=19$m=65536,t=2,p=1$49cWoO3+fsK3HOFu3cRc/g$BwhPqR5Bt ORXs3E0PU0S+uf9SSyRjMSr0AkA9VNM5yY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000')

  // Regression where errno was not set in libsodium, so mismatch would become
  // an input error
  t.throws(_ => sodium.crypto_pwhash_str_verify(malformedHashStr, password))
  t.notOk(sodium.crypto_pwhash_str_verify(hashStr, password))
  t.throws(_ => sodium.crypto_pwhash_str_verify(malformedHashStr, password))
  t.end()
})

tape('error conditions async', function (t) {
  var password = Buffer.from('changeme2')
  var hashStr = Buffer.from('$argon2id$v=19$m=65536,t=2,p=1$49cWoO3+fsK3HOFu3cRc/g$BwhPqR5BtORXs3E0PU0S+uf9SSyRjMSr0AkA9VNM5yY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000')
  var malformedHashStr = Buffer.from('$argon2id$v=19$m=65536,t=2,p=1$49cWoO3+fsK3HOFu3cRc/g$BwhPqR5Bt ORXs3E0PU0S+uf9SSyRjMSr0AkA9VNM5yY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000')

  // Regression where errno was not set in libsodium, so mismatch would become
  // an input error
  sodium.crypto_pwhash_str_verify_async(malformedHashStr, password, function (err, res) {
    t.ok(err)

    sodium.crypto_pwhash_str_verify_async(hashStr, password, function (err, res) {
      t.error(err)
      t.notOk(res)

      sodium.crypto_pwhash_str_verify_async(malformedHashStr, password, function (err, res) {
        t.ok(err)

        t.end()
      })
    })
  })
})

tape('minifuzz - sync', function (t) {
  var i = 1000

  var opslimit = sodium.crypto_pwhash_OPSLIMIT_MIN
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_MIN

  var passwords = [Buffer.from('hi'), Buffer.from('hello')]
  var hashes = passwords.map(function (pwd) {
    var hash = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
    sodium.crypto_pwhash_str(hash, pwd, opslimit, memlimit)
    return hash
  })
  hashes.push(Buffer.from(hashes[0]))
  hashes[2][30] = 45

  while (i--) {
    var pi = sodium.randombytes_uniform(passwords.length)
    var hi = sodium.randombytes_uniform(hashes.length)

    try {
      var correct = sodium.crypto_pwhash_str_verify(hashes[hi], passwords[pi])
    } catch (ex) {
      if (hi === pi) t.fail('caused error when should match')
      continue
    }

    if (correct && hi !== pi) t.fail('verified when should not match')
    if (!correct && hi === pi) t.fail('failed when should match')
  }

  t.end()
})

tape('minifuzz - async', function (t) {
  var i = 1000

  var opslimit = sodium.crypto_pwhash_OPSLIMIT_MIN
  var memlimit = sodium.crypto_pwhash_MEMLIMIT_MIN

  var passwords = [Buffer.from('hi'), Buffer.from('hello')]
  var hashes = [
    Buffer.alloc(sodium.crypto_pwhash_STRBYTES),
    Buffer.alloc(sodium.crypto_pwhash_STRBYTES),
    Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  ]

  sodium.crypto_pwhash_str_async(hashes[0], passwords[0], opslimit, memlimit, function (err) {
    t.error(err)

    sodium.crypto_pwhash_str_async(hashes[1], passwords[1], opslimit, memlimit, function (err) {
      t.error(err)

      hashes[2].set(hashes[0])
      hashes[2][30] = 45

      iterLoop(i)
    })
  })

  function iterLoop (n) {
    if (n === 0) return t.end()

    var pi = sodium.randombytes_uniform(passwords.length)
    var hi = sodium.randombytes_uniform(hashes.length)

    sodium.crypto_pwhash_str_verify_async(hashes[hi], passwords[pi], function (err, correct) {
      if (err && hi === pi) t.fail('caused error when should match')

      if (correct && hi !== pi) t.fail('verified when should not match')
      if (!correct && hi === pi) t.fail('failed when should match')

      iterLoop(n - 1)
    })
  }
})
