#!/usr/bin/env node

const https = require('https')
const child = require('child_process')
const fs = require('fs/promises')
const { createWriteStream: createFileWriteStream } = require('fs')
const stream = require('stream')
const path = require('path')
const os = require('os')

const IS_WINDOWS = process.platform === 'win32'
const VERSION = '1.0.18'
const VS = 'v141'
const MACOSX_DEPLOYMENT_TARGET = '10.10'

const UNIX = `https://download.libsodium.org/libsodium/releases/libsodium-${VERSION}.tar.gz`
const WIN = `https://download.libsodium.org/libsodium/releases/libsodium-${VERSION}-msvc.zip`

const UNIX_OUT = path.join(__dirname, 'unix')
const WIN_OUT = path.join(__dirname, 'win')

const TMP = path.join(__dirname, 'tmp')
const TMP_ZIP = path.join(TMP, 'win.zip')
const TMP_OUT = path.join(TMP, 'out')
const TMP_SRC = path.join(TMP, 'src')

const SRC = path.join(__dirname, 'libsodium-' + VERSION)

const ARCH = arg('arch') || process.env.PREBUILD_ARCH || os.arch()
const WARCH = ARCH === 'x64' ? 'x64' : 'Win32'
const QUIET = arg('print-include') || arg('print-lib') || arg('print-arch') || arg('quiet')

if (arg('print-arch')) {
  console.log(ARCH)
  process.exit(0)
}

const build = arg('clean')
  ? clean
  : arg('all')
    ? all
    : (IS_WINDOWS ? win : unix)

start()

async function start () {
  await rmf(TMP)
  try {
    await build()
  } catch (err) {
    console.error(err.stack)
    process.exit(1)
  }
  await rmf(TMP)
  if (arg('gyp')) {
    await nodeGyp()
  }
}

async function all () {
  await unix()
  await win()
}

async function unix () {
  await fetchUnix()
  await buildUnix()

  if (arg('print-lib')) {
    console.log(path.join(UNIX_OUT, 'lib/libsodium.a'))
  }

  if (arg('print-include')) {
    console.log(path.join(UNIX_OUT, 'include'))
  }
}

async function win () {
  await fetchWin()

  if (arg('print-lib')) {
    const vs = arg('vs') || VS
    const out = path.join(WIN_OUT, WARCH, 'Release')
    let found = null
    for (const version of await fs.readdir(out)) {
      if (vs) {
        if (vs === version) {
          found = version
          break
        }
      } else {
        if (!found || Number(version.replace('v', '')) > Number(found.replace('v', ''))) {
          found = version
        }
      }
    }

    if (!found) throw new Error('Could not find valid static library')

    console.log(path.join(out, found, 'static', 'libsodium.lib'))
  }

  if (arg('print-include')) {
    console.log(path.join(WIN_OUT, 'include'))
  }
}

async function nodeGyp () {
  await run(['node-gyp' + (IS_WINDOWS ? '.cmd' : ''), 'rebuild', '-v'], { cwd: path.join(__dirname, '..') })
}

async function buildUnix () {
  if (!(await flag('build', UNIX_OUT))) return

  await run(['./configure', '--prefix=' + TMP_OUT, '--enable-static', '--with-pic', '--disable-pie'], { cwd: SRC })
  await run(['make', 'clean'], { cwd: SRC })
  await run(['make', 'install'], { cwd: SRC })

  await rmf(UNIX_OUT)
  await fs.rename(TMP_OUT, UNIX_OUT)
}

async function fetchUnix () {
  if (!(await flag('fetch', SRC))) return

  await fs.mkdir(TMP_SRC, { recursive: true })
  const tar = await fetch(UNIX)
  await run(['tar', 'xzv'], { cwd: TMP_SRC, stdin: tar })

  // Atomically store it here
  await rmf(SRC)
  await fs.rename(path.join(TMP_SRC, 'libsodium-' + VERSION), SRC)
}

async function fetchWin () {
  if (!(await flag('fetch', WIN_OUT))) return

  const zip = await fetch(WIN)

  await fs.mkdir(TMP, { recursive: true })
  await new Promise((resolve, reject) => {
    stream.pipeline(zip, createFileWriteStream(TMP_ZIP), function (err) {
      if (err) reject(err)
      else resolve()
    })
  })

  if (process.platform === 'win32') {
    await run(['powershell', '-command', 'Expand-Archive win.zip out'], { cwd: TMP })
  } else {
    await run(['unzip', '-d', 'out', 'win.zip'], { cwd: TMP })
  }

  await fs.rename(path.join(TMP_OUT, 'libsodium'), WIN_OUT)
}

async function flag (name, folder) {
  if (process.argv.includes('--' + name)) return true
  if (process.argv.includes('--no-' + name)) return false

  try {
    await fs.stat(folder)
    return false
  } catch {
    return true
  }
}

async function clean () {
  await rmf(TMP)
  await rmf(SRC)
  await rmf(UNIX_OUT)
  await rmf(WIN_OUT)
}

async function rmf (dir) {
  try {
    await fs.stat(dir)
    await fs.rm(dir, { recursive: true })
  } catch {
    // do nothing
  }
}

function fetch (url) {
  return new Promise((resolve, reject) => {
    if (!QUIET) console.error('Fetching', url)
    https.get(url, function (res) {
      if (res.statusCode !== 200) return reject(new Error('Could not download ' + url + ' (' + res.statusCode + ')'))
      resolve(res)
    })
  })
}

function arg (name) {
  const i = process.argv.indexOf('--' + name)
  if (i === -1) return false
  if (process.argv.length <= i + 1 || process.argv[i + 1][0] === '-') return true
  return process.argv[i + 1]
}

function run (cmd, opts = {}) {
  return new Promise((resolve) => {
    const proc = child.spawn(cmd[0], cmd.slice(1), {
      cwd: opts.cwd || __dirname,
      stdio: [
        opts.stdin ? 'pipe' : 'ignore',
        QUIET ? 'ignore' : 2,
        QUIET ? 'ignore' : 2
      ],
      env: { MACOSX_DEPLOYMENT_TARGET, ...process.env }
    })

    if (opts.stdin) {
      opts.stdin.pipe(proc.stdin)
    }

    proc.on('exit', function (code) {
      if (code) process.exit(code)
      else resolve()
    })
  })
}
