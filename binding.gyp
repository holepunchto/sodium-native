{
  'variables': {
    'target_arch%': '<!(node deps/bin.js --print-arch)'
  },
  'targets': [
    {
      'target_name': 'sodium',
      'include_dirs' : [
        '<!(node deps/bin.js --print-include)'
      ],
      'sources': [
        'binding.c',
        './modules/crypto_tweak/tweak.c'
      ],
      'conditions': [
        ['OS=="win"', {
          'defines': [
            'SODIUM_STATIC=1',
            'SODIUM_EXPORT',
          ]
        }],
      ],
      'xcode_settings': {
        'OTHER_CFLAGS': [
          '-O3',
          '-Wall',
        ]
      },
      'cflags': [
        '-O3',
        '-Wall',
      ],
      'libraries': [
        '<!(node deps/bin.js --print-lib)'
      ]
    }
  ]
}
