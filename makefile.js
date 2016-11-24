var fs = require('fs')
var path = require('path')

var MAKEFILE = fs.readFileSync(path.join(__dirname, 'deps/libsodium/Makefile'), 'utf-8')
var DEFS = MAKEFILE.match(/DEFS = (.+)/)[1].replace(/\-D/g, '').replace(/\\"/g, '"').replace(/\\/, '')
var CFLAGS = MAKEFILE.match(/CFLAGS_.*/g).map(parseValue).filter(Boolean).join(' ')

if (process.argv.indexOf('--defines') > -1) console.log(DEFS)
if (process.argv.indexOf('--cflags') > -1) console.log(CFLAGS)

function parseValue (n) {
  return (n.split(' = ')[1] || '').trim()
}
