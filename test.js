const sodium = require('.')

var b1 = Buffer.from('hello')
var b2 = Buffer.from('olleh')
var a = new Uint32Array(4)
var b = new Uint32Array(4)
a[0] = 0x10
b[0] = 0x0

sodium.sodium_sub(a, b)
console.log(sodium.sodium_memcmp(b1, b2))
console.log(sodium.sodium_compare(a, b))
console.log(sodium.sodium_is_zero(b))
console.log(a)
sodium.sodium_increment(a)

const c = Buffer.alloc(32)
const d = Buffer.alloc(32)
sodium.randombytes_buf(c)
sodium.randombytes_buf_deterministic(d, d.slice())
console.log(c)
console.log(d)

sodium.sodium_pad(Buffer.alloc(20), 4, 4)

