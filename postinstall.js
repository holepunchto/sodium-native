var os = require('os')
var fs = require('fs')
var path = require('path')
var proc = require('child_process')

var release = path.join(__dirname, 'build/Release')
var debug = path.join(__dirname, 'build/Debug')
var build = fs.existsSync(release) ? release : debug
var arch = process.env.ARCH || os.arch()

switch (os.platform()) {
  case 'win32':
    buildWindows()
    break

  case 'darwin':
    buildDarwin()
    break

  case 'freebsd':
  case 'openbsd':
    buildBSD()
    break

  default:
    buildLinux()
    break
}

function buildWindows () {
  var lib = path.join(__dirname, 'lib/libsodium-' + arch + '.dll')
  var dst = path.join(build, 'libsodium.dll')
  if (fs.existsSync(dst)) return
  copy(lib, dst, function (err) {
    if (err) throw err
  })
}

function buildLinux () {
  var lib = path.join(__dirname, 'lib/libsodium-' + arch + '.so.23')
  var dst = path.join(build, 'libsodium.so.23')
  if (fs.existsSync(dst)) return
  copy(lib, dst, function (err) {
    if (err) throw err
  })
}

function buildBSD () {
  buildLinux()
}

function buildDarwin () {
  var lib = path.join(__dirname, 'lib/libsodium-' + arch + '.dylib')
  var dst = path.join(build, 'libsodium.dylib')
  if (fs.existsSync(dst)) return
  copy(lib, dst, function (err) {
    if (err) throw err
    proc.exec('install_name_tool -id "@loader_path/libsodium.dylib" libsodium.dylib', {cwd: build}, function (err) {
      if (err) throw err
      proc.exec('install_name_tool -change "' + lib + '" "@loader_path/libsodium.dylib" sodium.node', {cwd: build}, function (err) {
        if (err) throw err
      })
    })
  })
}

function copy (a, b, cb) {
  fs.stat(a, function (err, st) {
    if (err) return cb(err)
    fs.readFile(a, function (err, buf) {
      if (err) return cb(err)
      fs.writeFile(b, buf, function (err) {
        if (err) return cb(err)
        fs.chmod(b, st.mode, cb)
      })
    })
  })
}
