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

  t.is(sodium.crypto_kx_SEEDBYTES, 32)
  t.is(sodium.crypto_kx_PUBLICKEYBYTES, 32)
  t.is(sodium.crypto_kx_SESSIONKEYBYTES, 32)
  t.is(sodium.crypto_kx_SECRETKEYBYTES, 32)

  t.end()
})

/* eslint-disable camelcase */
test('libsodium', function (t) {
  const small_order_p = new Uint8Array([
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
    0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
    0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
  ])

  const seed = new Uint8Array(sodium.crypto_kx_SEEDBYTES)
  const client_pk = new Uint8Array(sodium.crypto_kx_PUBLICKEYBYTES)
  const client_sk = new Uint8Array(sodium.crypto_kx_SECRETKEYBYTES)
  const client_rx = new Uint8Array(sodium.crypto_kx_SESSIONKEYBYTES)
  const client_tx = new Uint8Array(sodium.crypto_kx_SESSIONKEYBYTES)
  const server_pk = new Uint8Array(sodium.crypto_kx_PUBLICKEYBYTES)
  const server_sk = new Uint8Array(sodium.crypto_kx_SECRETKEYBYTES)
  const server_rx = new Uint8Array(sodium.crypto_kx_SESSIONKEYBYTES)
  const server_tx = new Uint8Array(sodium.crypto_kx_SESSIONKEYBYTES)

  for (let i = 0; i < sodium.crypto_kx_SEEDBYTES; i++) {
    seed[i] = i
  }

  sodium.crypto_kx_seed_keypair(client_pk, client_sk, seed)

  const exp1 = new Uint8Array([
    0x0e, 0x02, 0x16, 0x22, 0x3f, 0x14, 0x71, 0x43, 0xd3, 0x26, 0x15,
    0xa9, 0x11, 0x89, 0xc2, 0x88, 0xc1, 0x72, 0x8c, 0xba, 0x3c, 0xc5,
    0xf9, 0xf6, 0x21, 0xb1, 0x02, 0x6e, 0x03, 0xd8, 0x31, 0x29
  ])

  const exp2 = new Uint8Array([
    0xcb, 0x2f, 0x51, 0x60, 0xfc, 0x1f, 0x7e, 0x05, 0xa5, 0x5e, 0xf4,
    0x9d, 0x34, 0x0b, 0x48, 0xda, 0x2e, 0x5a, 0x78, 0x09, 0x9d, 0x53,
    0x39, 0x33, 0x51, 0xcd, 0x57, 0x9d, 0xd4, 0x25, 0x03, 0xd6
  ])

  t.alike(client_pk, exp1, 'client_pk')
  t.alike(client_sk, exp2, 'client_pk')

  sodium.crypto_kx_keypair(server_pk, server_sk)

  t.exception(() => {
    sodium.crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, small_order_p)
  })

  t.execution(() => {
    sodium.crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk)
  })

  t.exception(() => sodium.crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, small_order_p))
  t.execution(() => {
    sodium.crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk)
  })

  t.alike(server_rx, client_tx)
  t.alike(server_tx, client_rx)

  sodium.sodium_increment(client_pk)

  t.execution(() => {
    sodium.crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk)
  })

  t.unlike(server_rx, client_tx)
  t.unlike(server_tx, client_rx)

  sodium.crypto_kx_keypair(client_pk, client_sk)

  t.execution(() => {
    sodium.crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk)
  })

  t.unlike(server_rx, client_tx)
  t.unlike(server_tx, client_rx)

  sodium.crypto_kx_seed_keypair(client_pk, client_sk, seed)
  sodium.sodium_increment(seed)

  sodium.crypto_kx_seed_keypair(server_pk, server_sk, seed)
  t.execution(() => {
    sodium.crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk)
  })

  const exp3 = new Uint8Array([
    0x62, 0xc8, 0xf4, 0xfa, 0x81, 0x80, 0x0a, 0xbd, 0x05, 0x77, 0xd9,
    0x99, 0x18, 0xd1, 0x29, 0xb6, 0x5d, 0xeb, 0x78, 0x9a, 0xf8, 0xc8,
    0x35, 0x1f, 0x39, 0x1f, 0xeb, 0x0c, 0xbf, 0x23, 0x86, 0x04
  ])

  const exp4 = new Uint8Array([
    0x74, 0x95, 0x19, 0xc6, 0x80, 0x59, 0xbc, 0xe6, 0x9f, 0x7c, 0xfc,
    0xc7, 0xb3, 0x87, 0xa3, 0xde, 0x1a, 0x1e, 0x82, 0x37, 0xd1, 0x10,
    0x99, 0x13, 0x23, 0xbf, 0x62, 0x87, 0x01, 0x15, 0x73, 0x1a
  ])

  t.alike(server_rx, exp3)
  t.alike(server_tx, exp4)

  t.execution(() => {
    sodium.crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk)
  })

  const exp5 = new Uint8Array([
    0x74, 0x95, 0x19, 0xc6, 0x80, 0x59, 0xbc, 0xe6, 0x9f, 0x7c, 0xfc,
    0xc7, 0xb3, 0x87, 0xa3, 0xde, 0x1a, 0x1e, 0x82, 0x37, 0xd1, 0x10,
    0x99, 0x13, 0x23, 0xbf, 0x62, 0x87, 0x01, 0x15, 0x73, 0x1a
  ])

  const exp6 = new Uint8Array([
    0x62, 0xc8, 0xf4, 0xfa, 0x81, 0x80, 0x0a, 0xbd, 0x05, 0x77, 0xd9,
    0x99, 0x18, 0xd1, 0x29, 0xb6, 0x5d, 0xeb, 0x78, 0x9a, 0xf8, 0xc8,
    0x35, 0x1f, 0x39, 0x1f, 0xeb, 0x0c, 0xbf, 0x23, 0x86, 0x04
  ])

  t.alike(client_rx, exp5)
  t.alike(client_tx, exp6)

  sodium.randombytes_buf(client_rx)
  sodium.randombytes_buf(client_tx)
  sodium.randombytes_buf(server_rx)
  sodium.randombytes_buf(server_tx)

  t.execution(() => sodium.crypto_kx_client_session_keys(client_rx, null,
    client_pk, client_sk, server_pk))
  t.execution(() => sodium.crypto_kx_client_session_keys(null, client_tx,
    client_pk, client_sk, server_pk))
  t.execution(() => sodium.crypto_kx_server_session_keys(server_rx, null,
    server_pk, server_sk, client_pk))
  t.execution(() => sodium.crypto_kx_server_session_keys(null, server_tx,
    server_pk, server_sk, client_pk))

  t.alike(client_rx, client_tx)
  t.alike(client_tx, server_rx)
  t.alike(server_rx, server_tx)
})
