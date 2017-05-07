var sodium = require('../..')
var buf = sodium.malloc(1)
sodium.mprotect_noaccess(buf)
buf[0]
process.send('read')
