const test = require('brittle')
const sodium = require('..')

test('crypto_kx_seed_keypair', function (t) {
  const pk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  const seed = Buffer.alloc(sodium.crypto_kx_SEEDBYTES, 'lo')

  t.exception.all(function () {
    sodium.crypto_kx_seed_keypair()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.crypto_kx_seed_keypair(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  sodium.crypto_kx_seed_keypair(pk, sk, seed)

  const eSk = '768475983073421d5b1676c4aabb24fdf17c3a5f19e6e9e9cdefbfeb45ceb153'
  const ePk = '0cd703bbd6b1d46dc431a1fc4f1f7724c64b1d4c471e8c17de4966c9e15bf85e'

  t.alike(pk.toString('hex'), ePk, 'seeded public key')
  t.alike(sk.toString('hex'), eSk, 'seeded secret key')
})

test('crypto_kx_keypair', function (t) {
  const pk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)

  sodium.crypto_kx_keypair(pk, sk)

  t.not(pk, Buffer.alloc(pk.length), 'made public key')
  t.not(sk, Buffer.alloc(sk.length), 'made secret key')

  t.exception.all(function () {
    sodium.crypto_kx_keypair()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.crypto_kx_keypair(Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')
})

test('crypto_kx_client_session_keys', function (t) {
  const clientPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const clientSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  const serverPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const serverSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)

  const serverRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  const serverTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  const clientRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  const clientTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  sodium.crypto_kx_keypair(serverPk, serverSk)
  sodium.crypto_kx_keypair(clientPk, clientSk)

  t.exception.all(function () {
    sodium.crypto_kx_client_session_keys()
  }, 'should validate')

  t.exception.all(function () {
    sodium.crypto_kx_server_session_keys()
  }, 'should validate')

  sodium.crypto_kx_client_session_keys(clientRx, clientTx, clientPk, clientSk, serverPk)
  sodium.crypto_kx_server_session_keys(serverRx, serverTx, serverPk, serverSk, clientPk)

  t.alike(clientRx, serverTx)
  t.alike(clientTx, serverRx)
})

test('crypto_kx_client_session_keys one NULL', function (t) {
  const clientPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const clientSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  const serverPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const serverSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)

  const serverRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  const serverTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  const clientRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  const clientTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  sodium.crypto_kx_keypair(serverPk, serverSk)
  sodium.crypto_kx_keypair(clientPk, clientSk)

  t.exception.all(function () {
    sodium.crypto_kx_client_session_keys()
  }, 'should validate')

  t.exception.all(function () {
    sodium.crypto_kx_server_session_keys()
  }, 'should validate')

  t.exception(function () {
    sodium.crypto_kx_server_session_keys(null, null, clientPk, clientSk, serverPk)
  }, 'should validate')

  t.exception(function () {
    sodium.crypto_kx_client_session_keys(null, null, clientPk, clientSk, serverPk)
  }, 'should validate')

  sodium.crypto_kx_client_session_keys(clientRx, null, clientPk, clientSk, serverPk)
  sodium.crypto_kx_server_session_keys(null, serverTx, serverPk, serverSk, clientPk)

  t.alike(clientRx, serverTx)

  sodium.crypto_kx_client_session_keys(null, clientTx, clientPk, clientSk, serverPk)
  sodium.crypto_kx_server_session_keys(serverRx, null, serverPk, serverSk, clientPk)
  t.alike(clientTx, serverRx)
})

test('crypto_kx constants', function (t) {
  t.alike(typeof sodium.crypto_kx_SESSIONKEYBYTES, 'number')
  t.alike(typeof sodium.crypto_kx_PUBLICKEYBYTES, 'number')
  t.alike(typeof sodium.crypto_kx_SECRETKEYBYTES, 'number')
  t.alike(typeof sodium.crypto_kx_SEEDBYTES, 'number')
  t.alike(typeof sodium.crypto_kx_PRIMITIVE, 'string')
})
