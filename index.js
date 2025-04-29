const binding = {} // require('./binding')
const { isNode } = require('which-runtime')

module.exports = binding

module.exports.sodium_malloc = function (size) {
  const buf = Buffer.from(binding._sodium_malloc(size))
  buf.secure = true
  return buf
}

module.exports.crypto_generichash = function (output, input, key) {
  return binding._crypto_generichash(output, input, !!key, key)
}

module.exports.crypto_generichash_init = function (state, key, outputLength) {
  return module.exports._crypto_generichash_init(state, !!key, key, outputLength)
}

module.exports.crypto_generichash_batch = function (output, batch, key) {
  const useKey = !!key
  if (isNode || batch.length < 12) {
    binding._crypto_generichash_batch(output, batch, useKey, key)
  } else {
    // fastcall batch
    const state = Buffer.alloc(binding.crypto_generichash_STATEBYTES)

    module.exports.crypto_generichash_init(state, key, output.byteLength)

    for (const buf of batch) {
      binding.crypto_generichash_update(state, buf)
    }

    binding.crypto_generichash_final(state, output)
  }
}

module.exports.crypto_secretstream_xchacha20poly1305_push = function (state, c, m, ad, tag) {
  return binding._crypto_secretstream_xchacha20poly1305_push(state, c, m, !!ad, ad, tag)
}

module.exports.crypto_secretstream_xchacha20poly1305_pull = function (state, m, tag, c, ad) {
  return binding._crypto_secretstream_xchacha20poly1305_pull(state, m, tag, c, !!ad, ad)
}

/**
 * Generates a JIT optimizable wrapper function that
 * spreads arraybuffer arguments and peforms bounds checks
 */
function wrap (fn, ...spec) {
  const names = []
  const args = []
  const ops = []

  for (const arg of spec) {
    // passthrough
    if (typeof arg === 'string') {
      names.push(arg)
      args.push(arg)
      continue
    }

    // buffer-argument
    const {
      name,
      optional,
      min,
      max,
      len,
      bounds
    } = arg

    names.push(name)

    const assertLength = (constant) => `
      if (${name}.byteLength !== binding.${constant}) {
        throw new Error('expected "${name}" to equal "${constant}"')
      }
    `.trim()

    const assertMinLength = (constant) => `
      if (${name}.byteLength < binding.${constant}) {
        throw new Error('expected "${name}" to be at least "${constant}"')
      }
    `.trim()

    const assertMaxLength = (constant) => `
      if (${name}.byteLength > binding.${constant}) {
        throw new Error('expected "${name}" to be at most "${constant}"')
      }
    `.trim()

    const assertBounds = (prefix) => `
      ${assertMinLength(prefix + '_MIN')}
      ${assertMaxLength(prefix + '_MAX')}
    `.trim()

    const asserts = []
    if (len) asserts.push(assertLength(len))
    if (min) asserts.push(assertMinLength(min))
    if (max) asserts.push(assertMaxLength(max))
    if (bounds) asserts.push(assertBounds(bounds))

    if (optional) {
      const conditionalAssert = `
        if (${name}) {
          ${asserts.join('\n')}
        } else {
          // ensure typed signature match
          ${name} = { buffer: null, byteOffset: 0, byteLength: 0 }
        }
      `.trim()
      ops.push(conditionalAssert)
    } else {
      ops.push(`if (!${name}) throw new Error('"${name}" must be an instance of TypedArray')`)
      ops.push(asserts.join('\n'))
    }

    // spread buffer into: arraybuffer, offset, length
    args.push(name + '.buffer')
    args.push(name + '.byteOffset')
    args.push(name + '.byteLength')
  }

  const body = `// Generated "${fn}" wrapper
    ${ops.join('\n')}

    const status = binding.${fn}(${args.join(', ')})

    if (status !== 0) throw new Error('"${fn}" failed')
  `.trim()

  module.exports[fn] = new Function(...names, body) // eslint-disable-line no-new-func
}

// test wrapper generator
/*
wrap('crypto_generichash',
  { name: 'input' },
  { name: 'output', bounds: 'crypto_generichash_BYTES' },
  { name: 'key', optional: true, bounds: 'crypto_generichash_KEYBYTES' }
)

console.log(module.exports.crypto_generichash.toString())

*/
