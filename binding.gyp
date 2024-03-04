{
  'targets': [{
    'target_name': 'sodium',
    'include_dirs': [
      './vendor/libsodium/src/libsodium/include',
    ],
    'dependencies': [
      './vendor/libsodium.gyp:libsodium',
    ],
    'defines': [
      'SODIUM_STATIC=1',
    ],
    'sources': [
      './binding.c',
      './modules/crypto_tweak/tweak.c'
    ],
    'configurations': {
      'Debug': {
        'defines': ['DEBUG'],
      },
      'Release': {
        'defines': ['NDEBUG'],
      },
    },
  }],
}
