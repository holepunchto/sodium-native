const test = require('brittle')
const sodium = require('..')

test('constants', function (t) {
  t.ok(
    sodium.crypto_pwhash_ALG_ARGON2I13 != null,
    'crypto_pwhash_ALG_ARGON2I13 is defined'
  )
  t.ok(
    sodium.crypto_pwhash_ALG_ARGON2ID13 != null,
    'crypto_pwhash_ALG_ARGON2ID13 is defined'
  )
  t.ok(
    sodium.crypto_pwhash_ALG_DEFAULT === sodium.crypto_pwhash_ALG_ARGON2ID13,
    'crypto_pwhash_ALG_DEFAULT is crypto_pwhash_ALG_ARGON2ID13'
  )
  t.ok(
    sodium.crypto_pwhash_BYTES_MIN != null,
    'crypto_pwhash_BYTES_MIN is defined'
  )
  t.ok(
    sodium.crypto_pwhash_BYTES_MAX != null,
    'crypto_pwhash_BYTES_MAX is defined'
  )
  t.ok(
    sodium.crypto_pwhash_PASSWD_MIN != null,
    'crypto_pwhash_PASSWD_MIN is defined'
  )
  t.ok(
    sodium.crypto_pwhash_PASSWD_MAX != null,
    'crypto_pwhash_PASSWD_MAX is defined'
  )
  t.ok(
    sodium.crypto_pwhash_SALTBYTES != null,
    'crypto_pwhash_SALTBYTES is defined'
  )
  t.ok(
    sodium.crypto_pwhash_STRBYTES != null,
    'crypto_pwhash_STRBYTES is defined'
  )

  t.ok(
    sodium.crypto_pwhash_OPSLIMIT_MIN != null,
    'crypto_pwhash_OPSLIMIT_MIN is defined'
  )
  t.ok(
    sodium.crypto_pwhash_OPSLIMIT_MAX != null,
    'crypto_pwhash_OPSLIMIT_MAX is defined'
  )
  t.ok(
    sodium.crypto_pwhash_MEMLIMIT_MIN != null,
    'crypto_pwhash_MEMLIMIT_MIN is defined'
  )
  t.ok(
    sodium.crypto_pwhash_MEMLIMIT_MAX != null,
    'crypto_pwhash_MEMLIMIT_MAX is defined'
  )
  t.ok(
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE != null,
    'crypto_pwhash_OPSLIMIT_INTERACTIVE is defined'
  )
  t.ok(
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE != null,
    'crypto_pwhash_MEMLIMIT_INTERACTIVE is defined'
  )
  t.ok(
    sodium.crypto_pwhash_OPSLIMIT_MODERATE != null,
    'crypto_pwhash_OPSLIMIT_MODERATE is defined'
  )
  t.ok(
    sodium.crypto_pwhash_MEMLIMIT_MODERATE != null,
    'crypto_pwhash_MEMLIMIT_MODERATE is defined'
  )
  t.ok(
    sodium.crypto_pwhash_OPSLIMIT_SENSITIVE != null,
    'crypto_pwhash_OPSLIMIT_SENSITIVE is defined'
  )
  t.ok(
    sodium.crypto_pwhash_MEMLIMIT_SENSITIVE != null,
    'crypto_pwhash_MEMLIMIT_SENSITIVE is defined'
  )
})

test('crypto_pwhash', function (t) {
  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  const algo = sodium.crypto_pwhash_ALG_DEFAULT

  sodium.crypto_pwhash(output, passwd, salt, opslimit, memlimit, algo)

  t.alike(
    output.toString('hex'),
    'f0236e17ec70050fc989f19d8ce640301e8f912154b4f0afc1552cdf246e659f',
    'hashes password'
  )

  salt[0] = 0
  sodium.crypto_pwhash(output, passwd, salt, opslimit, memlimit, algo)

  t.alike(
    output.toString('hex'),
    'df73f15d217196311d4b1aa6fba339905ffe581dee4bd3a95ec2bb7c52991d65',
    'diff salt -> diff hash'
  )
})

test('crypto_pwhash_str', function (t) {
  const output = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

  t.exception.all(function () {
    sodium.crypto_pwhash_str(output, passwd)
  }, 'should throw on missing args')

  sodium.crypto_pwhash_str(output, passwd, opslimit, memlimit)

  t.not(output, Buffer.alloc(output.length), 'not blank')
  t.absent(
    sodium.crypto_pwhash_str_verify(Buffer.alloc(output.length), passwd),
    'does not verify'
  )
  t.ok(sodium.crypto_pwhash_str_verify(output, passwd), 'verifies')
})

test('crypto_pwhash_str_needs_rehash', function (t) {
  const passwd = Buffer.from('secret')
  const weakMem = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const weakOps = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const malformed = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const good = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const weakAlg = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  weakAlg.set(
    Buffer.from(
      '$argon2id$v=19$m=8,t=1,p=1$DF4Tce8BK5di0gKeMBb2Fw$uNE4oyvyA0z68RPUom2NXu/KyGvpFppyUoN6pwFBtRU'
    )
  )

  sodium.crypto_pwhash_str(
    weakMem,
    passwd,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  )
  sodium.crypto_pwhash_str(
    weakOps,
    passwd,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE
  )
  sodium.crypto_pwhash_str(
    malformed,
    passwd,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE
  )
  sodium.crypto_pwhash_str(
    good,
    passwd,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE
  )

  const first$ = malformed.indexOf('$')
  const second$ = malformed.indexOf('$', first$ + 1)
  malformed.fill('p=,m=,', first$, second$, 'ascii')

  t.ok(
    sodium.crypto_pwhash_str_needs_rehash(
      weakMem,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE
    )
  )
  t.ok(
    sodium.crypto_pwhash_str_needs_rehash(
      weakOps,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE
    )
  )
  t.ok(
    sodium.crypto_pwhash_str_needs_rehash(
      weakAlg,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE
    )
  )
  t.absent(
    sodium.crypto_pwhash_str_needs_rehash(
      good,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE
    )
  )
  t.ok(
    sodium.crypto_pwhash_str_needs_rehash(
      malformed,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE
    )
  )
})

test('crypto_pwhash_async', function (t) {
  t.plan(4)

  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  const algo = sodium.crypto_pwhash_ALG_DEFAULT

  sodium.crypto_pwhash_async(
    output,
    passwd,
    salt,
    opslimit,
    memlimit,
    algo,
    function (err) {
      t.absent(err)
      t.alike(
        output.toString('hex'),
        'f0236e17ec70050fc989f19d8ce640301e8f912154b4f0afc1552cdf246e659f',
        'hashes password'
      )

      salt[0] = 0

      sodium.crypto_pwhash_async(
        output,
        passwd,
        salt,
        opslimit,
        memlimit,
        algo,
        function (err) {
          t.absent(err)
          t.alike(
            output.toString('hex'),
            'df73f15d217196311d4b1aa6fba339905ffe581dee4bd3a95ec2bb7c52991d65',
            'diff salt -> diff hash'
          )
        }
      )
    }
  )
})

test('crypto_pwhash_str_async', function (t) {
  t.plan(7)

  const output = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

  t.exception.all(function () {
    return sodium.crypto_pwhash_str_async(output, passwd)
  }, 'should throw on missing args')

  sodium.crypto_pwhash_str_async(
    output,
    passwd,
    opslimit,
    memlimit,
    function (err) {
      t.absent(err)
      t.not(output, Buffer.alloc(output.length), 'not blank')

      sodium.crypto_pwhash_str_verify_async(
        Buffer.alloc(output.length),
        passwd,
        function (err, bool) {
          t.absent(err)
          t.ok(bool === false, 'does not verify')

          sodium.crypto_pwhash_str_verify_async(
            output,
            passwd,
            function (err, bool) {
              t.absent(err)
              t.ok(bool === true, 'verifies')
            }
          )
        }
      )
    }
  )
})

test('crypto_pwhash_async promise', async function (t) {
  t.plan(4)

  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  const algo = sodium.crypto_pwhash_ALG_DEFAULT

  await t.execution(
    sodium.crypto_pwhash_async(output, passwd, salt, opslimit, memlimit, algo)
  )
  t.alike(
    output.toString('hex'),
    'f0236e17ec70050fc989f19d8ce640301e8f912154b4f0afc1552cdf246e659f',
    'hashes password'
  )

  salt[0] = 0

  await t.execution(
    sodium.crypto_pwhash_async(output, passwd, salt, opslimit, memlimit, algo)
  )
  t.alike(
    output.toString('hex'),
    'df73f15d217196311d4b1aa6fba339905ffe581dee4bd3a95ec2bb7c52991d65',
    'diff salt -> diff hash'
  )
})

test('crypto_pwhash_str_async promise', async function (t) {
  t.plan(7)

  const output = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

  t.exception.all(function () {
    sodium.crypto_pwhash_str_async(output, passwd)
  }, 'should throw on missing args')

  await t.execution(
    sodium.crypto_pwhash_str_async(output, passwd, opslimit, memlimit)
  )
  t.not(output, Buffer.alloc(output.length), 'not blank')

  let p = sodium.crypto_pwhash_str_verify_async(
    Buffer.alloc(output.length),
    passwd
  )
  await t.execution(p)
  t.ok((await p) === false, 'does not verify')

  p = sodium.crypto_pwhash_str_verify_async(output, passwd)
  await t.execution(p)
  t.ok((await p) === true, 'verifies')
})

test('crypto_pwhash limits', function (t) {
  const output = Buffer.alloc(sodium.crypto_pwhash_STRBYTES)
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = Number.MAX_SAFE_INTEGER
  const memlimit = Number.MAX_SAFE_INTEGER

  t.exception.all(function () {
    sodium.crypto_pwhash_str(output, passwd, opslimit, memlimit)
  }, 'should throw on large limits')
  t.exception.all(function () {
    sodium.crypto_pwhash_str(output, passwd, -1, -1)
  }, 'should throw on negative limits')
})

test('crypto_pwhash_async uncaughtException', function (t) {
  t.plan(1)

  const output = Buffer.alloc(32) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES, 'lo')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  const algo = sodium.crypto_pwhash_ALG_DEFAULT

  uncaught(listener)

  sodium.crypto_pwhash_async(
    output,
    passwd,
    salt,
    opslimit,
    memlimit,
    algo,
    exception
  )

  function exception() {
    throw new Error('caught')
  }

  function listener(err) {
    if (err.message !== 'caught') {
      t.fail()
    } else {
      t.pass()
    }
  }
})

test('crypto_pwhash_str_async uncaughtException', function (t) {
  t.plan(1)

  const output = Buffer.alloc(sodium.crypto_pwhash_STRBYTES) // can be any size
  const passwd = Buffer.from('Hej, Verden!')
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE

  uncaught(listener)

  sodium.crypto_pwhash_str_async(output, passwd, opslimit, memlimit, exception)

  function exception() {
    throw new Error('caught')
  }

  function listener(err) {
    if (err.message === 'caught') {
      t.pass()
    } else {
      t.fail()
    }
  }
})

test('crypto_pwhash_str_verify_async uncaughtException', function (t) {
  t.plan(1)

  const output = Buffer.alloc(sodium.crypto_pwhash_STRBYTES) // can be any size
  const passwd = Buffer.from('Hej, Verden!')

  uncaught(listener)

  sodium.crypto_pwhash_str_verify_async(output, passwd, exception)

  function exception() {
    throw new Error('caught')
  }

  function listener(err) {
    if (err.message === 'caught') {
      t.pass()
    } else {
      t.fail()
    }
  }
})

function uncaught(fn) {
  if (global.Bare) {
    global.Bare.once('uncaughtException', fn)
  } else {
    process.once('uncaughtException', fn)
  }
}
