var sodium = require('../..')
var buf = sodium.malloc(1)
sodium.mprotect_noaccess(buf)
sodium.mprotect_readwrite(buf)
buf[0]
process.send('read')
buf[0] = 1
process.send('write')
sodium.mprotect_readonly(buf)
process.send(buf[0] === 1 ? 'did_write' : 'did_not_write')
