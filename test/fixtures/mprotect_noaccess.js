/* eslint-disable */
const sodium = require('../..')
const buf = sodium.sodium_malloc(1)
sodium.sodium_mprotect_noaccess(buf)
buf[0]
process.send('read')
