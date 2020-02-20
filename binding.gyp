{
  'variables': {
    'target_arch%': '<!(node preinstall.js --print-arch)>'
  },
  'targets': [
    {
      'target_name': 'sodium',
      'include_dirs' : [
        'libsodium/src/libsodium/include'
      ],
      'sources': [
        'binding.c'
      ],
      'xcode_settings': {
        'OTHER_CFLAGS': [
          '-g',
          '-O3',
          '-Wall',
          '-pedantic-errors',
        ]
      },
      'cflags': [
        '-g',
        '-O3',
        '-Wall',
        '-pedantic-errors',
      ],
      'libraries': [
        '<!(node preinstall.js --print-lib)'
      ],
      'conditions': [
        ['OS != "mac" and OS != "win"', {
          'link_settings': {
            'libraries': [ "-Wl,-rpath=\\$$ORIGIN"]
          }
        }],
      ],
    }
  ]
}
