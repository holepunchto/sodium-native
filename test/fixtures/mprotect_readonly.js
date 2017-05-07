var sodium = require('../..')
var buf = sodium.malloc(1)
sodium.mprotect_readonly(buf)
buf[0]
process.send('read')
buf[0] = 1
process.send('write')
