{
    'variables': {
        'target_arch%': '<!(node -p "os.arch()")>'
    },
    'targets': [{
        'target_name': 'sodium',
        'include_dirs': ['<!(node -e "require(\'nan\')")',
            '<!(node -p "require(\'libsodium-prebuilt/paths\').include")'
        ],
        'sources': [
            'binding.cc',
            'src/crypto_hash_sha256_wrap.cc',
            'src/crypto_hash_sha512_wrap.cc',
            'src/crypto_generichash_wrap.cc',
            'src/crypto_onetimeauth_wrap.cc',
            'src/crypto_stream_xor_wrap.cc',
            'src/crypto_stream_chacha20_xor_wrap.cc',
            'src/crypto_secretstream_xchacha20poly1305_state_wrap.cc',
            'src/crypto_pwhash_async.cc',
            'src/crypto_pwhash_str_async.cc',
            'src/crypto_pwhash_str_verify_async.cc',
        ],
        'xcode_settings': {
            'OTHER_CFLAGS': ['-g', '-O3']
        },
        'cflags': ['-g', '-O3'],
        'conditions': [
            ['OS == "win"', {
                'link_settings': {
                    'libraries': [
                        '<!(node -p "require(\'libsodium-prebuilt/paths\').win32lib")',
                    ]
                },
                'msvs_settings': {
                    'VCLinkerTool': {
                        'DelayLoadDLLs': ['<!(node -p "require(\'libsodium-prebuilt/paths\').win32dll")']
                    }
                },
            }],
            ['OS == "mac"', {
              'link_settings': {
                  'libraries': [
                      '-L<!(node -p "require(\'libsodium-prebuilt/paths\').lib")',
                      '-lazy-lsodium',
                  ]
              }
            }],
            ['OS == "linux"', {
                'link_settings': {
                    'libraries': [
                        '-L<!(node -p \'require("libsodium-prebuilt/paths").lib\')',
                        '-z lazy',
                        '-lsodium',
                    ]
                }
            }]
        ],
    }]
}
