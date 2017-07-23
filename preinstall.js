#!/usr/bin/env node

var fs = require('fs')
var os = require('os')
var proc = require('child_process')
var path = require('path')

var dir = path.join(__dirname, 'deps/libsodium')
var tmp = path.join(__dirname, 'tmp')
var arch = process.env.PREBUILD_ARCH || os.arch()

if (process.argv.indexOf('--arch') > -1) {
  arch = process.argv[process.argv.indexOf('--arch') + 1]
}

var warch = arch === 'x64' ? 'x64' : 'Win32'

if (process.argv.indexOf('--print-arch') > -1) {
  console.log(arch)
  process.exit(0)
}

if (process.argv.indexOf('--print-lib') > -1) {
  switch (os.platform()) {
    case 'darwin':
      console.log('../deps/lib/libsodium-' + arch + '.dylib')
      break
    case 'openbsd':
      console.log(path.join(__dirname, '/deps/lib/libsodium-' + arch + '.so.20.0'))
      break
    case 'win32':
      console.log('../deps/libsodium/Build/ReleaseDLL/' + warch + '/libsodium.lib')
      break

    default:
      console.log(path.join(__dirname, '/deps/lib/libsodium-' + arch + '.so.18'))
      break
  }
}

try {
  fs.mkdirSync(path.join(__dirname, 'deps/lib'))
} catch (err) {
  // do nothing
}

switch (os.platform()) {
  case 'darwin':
    buildDarwin()
    break

  case 'win32':
    buildWindows()
    break

  case 'openbsd':
    buildBSD()
    break

  default:
    buildLinux()
    break
}

function buildWindows () {
  var res = path.join(__dirname, 'deps/lib/libsodium-' + arch + '.dll')
  if (fs.existsSync(res)) return

  spawn('.\\msvc-scripts\\process.bat', [], {cwd: dir, stdio: 'inherit'}, function (err) {
    if (err) throw err
    var msbuild = path.resolve('/', 'Program Files (x86)', 'MSBuild/14.0/Bin/MSBuild.exe')
    var args = ['/p:Configuration=ReleaseDLL;Platform=' + warch, '/nologo']
    spawn(msbuild, args, {cwd: dir, stdio: 'inherit'}, function (err) {
      if (err) throw err

      var dll = path.join(dir, 'Build/ReleaseDLL/' + warch + '/libsodium.dll')

      fs.rename(dll, res, function (err) {
        if (err) throw err
      })
    })
  })
}

function buildUnix (ext, cb) {
  var res = path.join(__dirname, 'deps/lib/libsodium-' + arch + '.' + ext)
  if (fs.existsSync(res)) return cb(null, res)

  spawn('./configure', ['--prefix=' + tmp], {cwd: dir, stdio: 'inherit'}, function (err) {
    if (err) throw err
    spawn('make', ['clean'], {cwd: dir, stdio: 'inherit'}, function (err) {
      if (err) throw err
      spawn('make', ['install'], {cwd: dir, stdio: 'inherit'}, function (err) {
        if (err) throw err

        var lib = fs.realpathSync(path.join(tmp, 'lib/libsodium.' + ext))
        fs.rename(lib, res, function (err) {
          if (err) throw err
          if (cb) cb(null, res)
        })
      })
    })
  })
}

function buildDarwin () {
  buildUnix('dylib', function (err, res) {
    if (err) throw err
    spawn('install_name_tool', ['-id', res, res], {stdio: 'inherit'}, function (err) {
      if (err) throw err
    })
  })
}

function buildBSD () {
  buildUnix('so.20.0', function (err) {
    if (err) throw err
  })
}

function buildLinux () {
  buildUnix('so.18', function (err) {
    if (err) throw err
  })
}

function spawn (cmd, args, opts, cb) {
  var c = proc.spawn(cmd, args, opts)
  c.on('exit', function (code) {
    if (code) return cb(new Error(cmd + ' exited with ' + code))
    cb(null)
  })
}
