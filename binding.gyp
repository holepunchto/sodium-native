{
  'targets': [
    {
      'target_name': 'libsodium',
      'dependencies': [
        'deps/libsodium.gyp:libsodium',
      ],
      'include_dirs' : [
        "<!(node -e \"require('nan')\")",
        'deps/libsodium',
        'deps/libsodium/src/libsodium/include'
      ],
      'sources': [
        'binding.cc',
        'src/crypto_generichash_wrap.cc',
        'src/crypto_onetimeauth_wrap.cc',
      ],
      'xcode_settings': {
        'OTHER_CFLAGS': [
          '-g',
          '-O3',
        ]
      },
      'cflags': [
        '-g',
        '-O3',
      ]
    }
  ]
}
