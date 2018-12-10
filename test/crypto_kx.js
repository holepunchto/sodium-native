var tape = require('tape')
var sodium = require('../')

tape('crypto_kx_seed_keypair', function (t) {
  var pk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  var seed = Buffer.alloc(sodium.crypto_kx_SEEDBYTES, 'lo')

  t.throws(function () {
    sodium.crypto_kx_seed_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_kx_seed_keypair(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  sodium.crypto_kx_seed_keypair(pk, sk, seed)

  var eSk = '768475983073421d5b1676c4aabb24fdf17c3a5f19e6e9e9cdefbfeb45ceb153'
  var ePk = '0cd703bbd6b1d46dc431a1fc4f1f7724c64b1d4c471e8c17de4966c9e15bf85e'

  t.same(pk.toString('hex'), ePk, 'seeded public key')
  t.same(sk.toString('hex'), eSk, 'seeded secret key')
  t.end()
})

tape('crypto_kx_keypair', function (t) {
  var pk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)

  sodium.crypto_kx_keypair(pk, sk)

  t.notEqual(pk, Buffer.alloc(pk.length), 'made public key')
  t.notEqual(sk, Buffer.alloc(sk.length), 'made secret key')

  t.throws(function () {
    sodium.crypto_kx_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_kx_keypair(Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  t.end()
})

tape('crypto_kx_client_session_keys', function (t) {
  var clientPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  var clientSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  var serverPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  var serverSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)

  var serverRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  var serverTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  var clientRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  var clientTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  sodium.crypto_kx_keypair(serverPk, serverSk)
  sodium.crypto_kx_keypair(clientPk, clientSk)

  t.throws(function () {
    sodium.crypto_kx_client_session_keys()
  }, 'should validate')

  t.throws(function () {
    sodium.crypto_kx_server_session_keys()
  }, 'should validate')

  sodium.crypto_kx_client_session_keys(clientRx, clientTx, clientPk, clientSk, serverPk)
  sodium.crypto_kx_server_session_keys(serverRx, serverTx, serverPk, serverSk, clientPk)

  t.same(clientRx, serverTx)
  t.same(clientTx, serverRx)
  t.end()
})

tape('crypto_kx_client_session_keys one NULL', function (t) {
  var clientPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  var clientSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  var serverPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  var serverSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)

  var serverRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  var serverTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  var clientRx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  var clientTx = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)

  sodium.crypto_kx_keypair(serverPk, serverSk)
  sodium.crypto_kx_keypair(clientPk, clientSk)

  t.throws(function () {
    sodium.crypto_kx_client_session_keys()
  }, 'should validate')

  t.throws(function () {
    sodium.crypto_kx_server_session_keys()
  }, 'should validate')

  t.throws(function () {
    sodium.crypto_kx_server_session_keys(null, null, clientPk, clientSk, serverPk)
  }, 'should validate')

  t.throws(function () {
    sodium.crypto_kx_client_session_keys(null, null, clientPk, clientSk, serverPk)
  }, 'should validate')

  sodium.crypto_kx_client_session_keys(clientRx, null, clientPk, clientSk, serverPk)
  sodium.crypto_kx_server_session_keys(null, serverTx, serverPk, serverSk, clientPk)

  t.same(clientRx, serverTx)

  sodium.crypto_kx_client_session_keys(null, clientTx, clientPk, clientSk, serverPk)
  sodium.crypto_kx_server_session_keys(serverRx, null, serverPk, serverSk, clientPk)
  t.same(clientTx, serverRx)
  t.end()
})

tape('crypto_kx constants', function (t) {
  t.same(typeof sodium.crypto_kx_SESSIONKEYBYTES, 'number')
  t.same(typeof sodium.crypto_kx_PUBLICKEYBYTES, 'number')
  t.same(typeof sodium.crypto_kx_SECRETKEYBYTES, 'number')
  t.same(typeof sodium.crypto_kx_SEEDBYTES, 'number')
  t.same(typeof sodium.crypto_kx_PRIMITIVE, 'string')
  t.end()
})
