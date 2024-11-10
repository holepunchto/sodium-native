const path = require('path')
const fs = require('fs')

const [sodium] = process.argv.slice(2)

const version = '1.0.18'

const file = fs.readFileSync(path.join(sodium, 'src/libsodium/include/sodium/version.h.in'), 'utf-8')
  .replace('@VERSION@', version)
  .replace('@SODIUM_LIBRARY_VERSION_MAJOR@', 26)
  .replace('@SODIUM_LIBRARY_VERSION_MINOR@', 2)
  .replace('@SODIUM_LIBRARY_MINIMAL_DEF@', '')

fs.writeFileSync(path.join(sodium, 'src/libsodium/include/sodium/version.h'), file)

process.stdout.write(version)
