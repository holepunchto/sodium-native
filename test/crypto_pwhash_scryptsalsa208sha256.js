const test = require('brittle')
const sodium = require('..')

test('constants', function (t) {
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
})

test('crypto_pwhash_scryptsalsa208sha256', function (t) {
  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  sodium.crypto_pwhash_scryptsalsa208sha256(output, passwd, salt, opslimit, memlimit)

  t.alike(output.toString('hex'), 'c9d280362d495e494672e44a91b94b35bb295f62c823845dd19773ded5877c2b', 'hashes password')

  salt[0] = 0
  sodium.crypto_pwhash_scryptsalsa208sha256(output, passwd, salt, opslimit, memlimit)

  t.alike(output.toString('hex'), '3831bd383708c7aff661ab4f990b116c7287bafde9abd02db3174631c97042e6', 'diff salt -> diff hash')
})

test('crypto_pwhash_scryptsalsa208sha256_str', function (t) {
  const output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  sodium.crypto_pwhash_scryptsalsa208sha256_str(output, passwd, opslimit, memlimit)

  t.not(output, Buffer.alloc(output.length), 'not blank')
  t.absent(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(Buffer.alloc(output.length), passwd), 'does not verify')
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(output, passwd), 'verifies')
})

test('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash', function (t) {
  const passwd = Buffer.from('secret')
  const weakMem = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const weakOps = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const malformed = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const good = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const weakAlg = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  weakAlg.set('argon2i$p=2,v=19,m=1024$SGVsbG8=$SGVsbG8gd29ybA==')

  sodium.crypto_pwhash_scryptsalsa208sha256_str(weakMem, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE)
  sodium.crypto_pwhash_scryptsalsa208sha256_str(weakOps, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)
  sodium.crypto_pwhash_scryptsalsa208sha256_str(malformed, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)
  sodium.crypto_pwhash_scryptsalsa208sha256_str(good, passwd, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)

  const first$ = malformed.indexOf('$')
  const second$ = malformed.indexOf('$', first$ + 1)
  malformed.fill('p=,m=,', first$, second$, 'ascii')

  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(weakMem, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(weakOps, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(weakAlg, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.absent(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(good, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
  t.ok(sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(malformed, sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE))
})

test('crypto_pwhash_scryptsalsa208sha256_async', function (t) {
  t.plan(4)

  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit, function (err) {
    t.absent(err)
    t.alike(output.toString('hex'), 'c9d280362d495e494672e44a91b94b35bb295f62c823845dd19773ded5877c2b', 'hashes password')

    salt[0] = 0
    sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit, function (err) {
      t.absent(err)
      t.alike(output.toString('hex'), '3831bd383708c7aff661ab4f990b116c7287bafde9abd02db3174631c97042e6', 'diff salt -> diff hash')
    })
  })
})

test('crypto_pwhash_scryptsalsa208sha256_str_async', function (t) {
  t.plan(6)

  const output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  sodium.crypto_pwhash_scryptsalsa208sha256_str_async(output, passwd, opslimit, memlimit, function (err) {
    t.absent(err)
    t.not(output, Buffer.alloc(output.length), 'not blank')

    sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(Buffer.alloc(output.length), passwd, function (err, bool) {
      t.absent(err)
      t.ok(bool === false, 'does not verify')

      sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(output, passwd, function (err, bool) {
        t.absent(err)
        t.ok(bool === true, 'verifies')
      })
    })
  })
})

test('crypto_pwhash_scryptsalsa208sha256 limits', function (t) {
  const output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = Number.MAX_SAFE_INTEGER
  const memlimit = Number.MAX_SAFE_INTEGER

  t.exception.all(function () {
    sodium.crypto_pwhash_scryptsalsa208sha256_str(output, passwd, opslimit, memlimit)
  }, 'should throw on large limits')
  t.exception.all(function () {
    sodium.crypto_pwhash_scryptsalsa208sha256_str(output, passwd, -1, -1)
  }, 'should throw on negative limits')
})

test('crypto_pwhash_scryptsalsa208sha256_async uncaughtException', function (t) {
  t.plan(1)

  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  uncaught(listener)

  sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit, exception)

  function exception () {
    throw new Error('caught')
  }

  function listener (err) {
    if (err.message !== 'caught') {
      t.fail()
    } else {
      t.pass()
    }
  }
})

test('crypto_pwhash_scryptsalsa208sha256_str_async uncaughtException', function (t) {
  t.plan(1)

  const output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  uncaught(listener)

  sodium.crypto_pwhash_scryptsalsa208sha256_str_async(output, passwd, opslimit, memlimit, exception)

  function exception () {
    throw new Error('caught')
  }

  function listener (err) {
    if (err.message === 'caught') {
      t.pass()
    } else {
      t.fail()
    }
  }
})

test('crypto_pwhash_scryptsalsa208sha256_str_verify_async uncaughtException', function (t) {
  t.plan(1)

  const output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES) // can be any size
  const passwd = Buffer.from('Hej, Verden!')

  uncaught(listener)

  sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(output, passwd, exception)

  function exception () {
    throw new Error('caught')
  }

  function listener (err) {
    if (err.message === 'caught') {
      t.pass()
    } else {
      t.fail()
    }
  }
})

test('crypto_pwhash_scryptsalsa208sha256_async promise', async function (t) {
  t.plan(4)

  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  await t.execution(sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit))
  t.alike(output.toString('hex'), 'c9d280362d495e494672e44a91b94b35bb295f62c823845dd19773ded5877c2b', 'hashes password')

  salt[0] = 0

  await t.execution(sodium.crypto_pwhash_scryptsalsa208sha256_async(output, passwd, salt, opslimit, memlimit))
  t.alike(output.toString('hex'), '3831bd383708c7aff661ab4f990b116c7287bafde9abd02db3174631c97042e6', 'diff salt -> diff hash')
})

test('crypto_pwhash_scryptsalsa208sha256_str_async promise', async function (t) {
  t.plan(5)

  const output = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  await sodium.crypto_pwhash_scryptsalsa208sha256_str_async(output, passwd, opslimit, memlimit)
  t.not(output, Buffer.alloc(output.length), 'not blank')

  let p = await sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(Buffer.alloc(output.length), passwd)
  await t.execution(p)
  t.ok(p === false, 'does not verify')

  p = await sodium.crypto_pwhash_scryptsalsa208sha256_str_verify_async(output, passwd)
  await t.execution(p)
  t.ok(p === true, 'verifies')
})

function uncaught (fn) {
  if (global.Bare) {
    global.Bare.once('uncaughtException', fn)
  } else {
    process.once('uncaughtException', fn)
  }
}
