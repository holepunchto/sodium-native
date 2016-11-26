{
    'targets': [
        {
            'target_name': 'libsodium',
            'variables': {
                'target_arch%': "<!(node -e \"console.log(require('os').arch())\")",
            },
            'type': 'static_library',
            'dependencies': [],
            'defines': [
                'NDEBUG',
                'SODIUM_STATIC',
                'HAVE_LIBM=1',
                '<!@(node ../makefile.js --defines)',
            ],
            'include_dirs': [
                'libsodium/src/libsodium/include/sodium',
            ],
            'xcode_settings': {
                'OTHER_CFLAGS': [
                        '-fPIC',
                        '-fwrapv',
                        '-fno-strict-aliasing',
                        '-fstack-protector-all',
                        '-Winit-self',
                        '-Wwrite-strings',
                        '-Wdiv-by-zero',
                        '-Wmissing-braces',
                        '-Wmissing-field-initializers',
                        '-Wno-sign-compare',
                        '-Wno-unused-const-variable',
                        '-g',
                        '-O3',
                        '-fvisibility=hidden',
                        '-Wno-missing-field-initializers',
                        '-Wno-missing-braces',
                        '-Wno-unused-function',
                        '-Wno-strict-overflow',
                        '-Wno-unknown-pragmas',
                        '<!@(node ../makefile.js --cflags)',
                ],
                'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
            },
            '!cflags': ['-fno-exceptions'],
            'cflags': [
                '-fexceptions',
                '-Winit-self',
                '-Wwrite-strings',
                '-Wdiv-by-zero',
                '-Wmissing-braces',
                '-Wmissing-field-initializers',
                '-Wno-sign-compare',
                '-Wno-unused-but-set-variable',
                '-g',
                '-O3',
                '-Wno-unknown-pragmas',
                '-Wno-missing-field-initializers',
                '-Wno-missing-braces',
                '<!@(node ../makefile.js --cflags)',
            ],
            'ldflags': [
                '-pie',
                '-Wl',
                '-z',
                'relro'
                '-z',
                'now'
                '-Wl',
                '-z',
                'noexecstack'
            ],
            'sources': [
              '<!@(find libsodium/src -name \'*.[c|h|S]\' | grep -v include)'
            ]
        }
    ]
}
