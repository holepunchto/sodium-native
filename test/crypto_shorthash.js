const test = require('brittle')
const sodium = require('..')

const vectors = [
  // generated from https://github.com/jedisct1/siphash-js/blob/master/test/index.js
  [
    'aON1dHrq90SbG8Hx',
    'v7LyiwuCrB7EgAibPve6Yg2gLmggxE6j7ocR37EudrH_P9XX2rQK',
    [147, 73, 50, 63, 71, 98, 203, 42]
  ],
  [
    'YOT4AG5F7ONRW5na',
    '4Ks1pPO_2wGYR-gfJShqUO-FirA9c5cF4oKwvStp2Ix5hHUg2klPofVJ8TZoBdFfgTh8',
    [138, 27, 129, 27, 185, 163, 160, 153]
  ],
  [
    '63UlqXfSckA3Dv8S',
    'bMQudI8yVdDx5ScGQCMQy4K_QXYCq1w1eC',
    [6, 78, 44, 167, 186, 29, 113, 244]
  ],
  [
    'P3hpmZEuwfDO_uZ-',
    'Wh8yRitk__n4MsETCTRFrB4bjWRtPjUZVLPnywlvv5nTMA2C71',
    [241, 171, 151, 44, 166, 163, 156, 234]
  ],
  ['d9oTrpd-a_Na4b6w', 'f-NT', [182, 147, 203, 88, 65, 57, 119, 203]],
  [
    'fe88HBnyyEiuIJ8G',
    'KSWP9sFkhSdGsha0Fmd5raCf_eA5gnV1',
    [218, 10, 3, 10, 16, 50, 241, 229]
  ],
  ['o6LxtnACG0RGQ3z-', 'k8zMl', [16, 158, 19, 145, 214, 142, 177, 55]],
  [
    'AHGkoQQ6xdf90MD9',
    'HC9bz8XUYkan0jxYSaj0vP-cs324Y4PrnAXutwKBgIko5oOOOViJSjLD2m8WenV8HdF78J',
    [157, 186, 255, 238, 165, 21, 187, 163]
  ],
  ['TlVmpfbZMFkeuENo', '5is', [166, 36, 114, 58, 101, 106, 79, 30]],
  ['iBLscVfsPM1xrSFJ', 'J-aH-', [14, 91, 64, 158, 190, 247, 72, 26]],
  [
    'hUehErdKolgd0erH',
    'DhS94w_07-vaAXo_msv8Fk57slIHnuxy3iv4Yymh5k',
    [45, 207, 192, 24, 158, 243, 93, 68]
  ],
  [
    'B-aq-09jmO0z_PUD',
    '1p2IMG4A1NMyWsfUS02VK8fOEhn',
    [161, 224, 65, 80, 91, 44, 131, 177]
  ],
  ['fyNYE8SMJvYrDgao', 'HWCtQs19BHZcH', [122, 114, 254, 14, 124, 226, 23, 173]],
  [
    '5vQHK_yJlJez45N5',
    '8YJwfpxwbH9h-N27i-uTUUK2Vt',
    [142, 216, 87, 77, 16, 17, 8, 199]
  ],
  [
    'q7Oo0g9DDjLJ_pyV',
    'jQFAHtrTUDaCaSIcis5h2j4fyOJpJGfdZBMTO5GOAAB4AwZtutDenNZ',
    [230, 111, 182, 25, 233, 231, 14, 141]
  ],
  [
    'IUle6P8g2uyX_8ms',
    'hOKGFGrsAux60CQmbOjQd-EzQBKUjLbDUhhtsKt3ZY4',
    [64, 247, 102, 236, 211, 145, 4, 152]
  ],
  ['-bZa23onpInwqNWG', 'DNbtZuulH9', [247, 2, 142, 172, 208, 100, 60, 127]],
  ['1xjmLXTmVJwse8M-', 'j1_Hh', [197, 81, 6, 184, 57, 173, 83, 126]],
  ['Ey7hygEVd8RxZdtX', 'GNRDNJDu00L', [137, 196, 184, 4, 146, 27, 188, 191]],
  [
    'weTzikz4EGUbhSgC',
    'g1SXT7b4Zz6q2tQykV1tZS',
    [105, 39, 69, 220, 198, 210, 96, 240]
  ],
  [
    'OjSaplYVoQPDXG7S',
    'QCk4v3D9s6R471p0xa--Vv00vzIaMpJ1S48Qnz6uzhmtke99HmWcY9vapyjdWVS',
    [183, 208, 142, 194, 95, 247, 239, 122]
  ],
  [
    '4g2ZB-SA-HlqJT7D',
    'N5Ht5QIk6KziyTE4-q5eNkqGdQgg8fxkr4w-ARqRgdaZd3XpbePGGb4jPFo3',
    [127, 245, 152, 248, 155, 148, 212, 127]
  ],
  [
    'CXOF2EKm5CDPYpNC',
    'xkY0T8bPF4JFq6Mu0K5YtFp7KfOni',
    [124, 172, 24, 66, 198, 236, 234, 226]
  ],
  ['ID4UzFBiztXW--b0', 'qyICNMPaivgDmX', [46, 95, 156, 18, 186, 88, 188, 122]],
  ['TaGesMDe_0UNGzcp', 'nlNv', [103, 245, 211, 70, 87, 104, 0, 17]],
  ['lMDS8Vcs-8aCV9hJ', 'KW44Qk', [69, 47, 130, 50, 196, 101, 206, 62]],
  [
    'BmQCaB-c777zvFsc',
    'o-tr2zQVbtrmkH4rCCAXoXFt8KwAWo4YFpK',
    [123, 168, 235, 94, 113, 233, 190, 213]
  ],
  [
    'OQlCpJOLmsouyme1',
    'aRk9nyHhXlad-TpIemD2VTRiHVlzSysY7uKof9ApR5DejFjT-Bmdzl_z',
    [89, 201, 222, 238, 50, 99, 249, 215]
  ],
  [
    't6Wl3FKDhr9FAMzz',
    'BLu17bk_iQtpGv1N4A',
    [80, 7, 121, 129, 115, 84, 153, 140]
  ],
  [
    'XU5km7La0ujNVvlV',
    'OUEAH4yu6SXQ4I8zjn07NuB_AudmoewXc39HqgN8rc',
    [220, 180, 100, 142, 210, 176, 72, 108]
  ],
  ['zDKBNpM2cdf0HwkK', 'dEqgpqTRc', [221, 42, 57, 242, 197, 147, 27, 81]],
  [
    'yZGrKEShM0z7Vvns',
    'sgUtgxRQpMl_o6iuZqomKhJxaSBCD_NBHa2lqX3cWfq8byu',
    [211, 179, 114, 59, 129, 223, 168, 65]
  ],
  ['4-wM8GXg1a7hyerE', 'djJ3-b2', [157, 165, 254, 119, 109, 239, 114, 115]],
  [
    'jD3Y4PgdExHU2JaY',
    'uQC59dKTf3unOGu-Lg9IgmC8MTSg-BcH-',
    [249, 179, 174, 181, 118, 232, 40, 255]
  ],
  [
    'dZhRW8ubIZovieQg',
    'GCbxph1HICSKgHLafk_8TRjGdZa7jnJOu',
    [73, 24, 76, 226, 201, 86, 43, 223]
  ],
  [
    'P9hudzT3H87QzC9E',
    'Vfeo26fUa3sLk6BNM',
    [31, 150, 174, 223, 224, 214, 127, 107]
  ],
  [
    'ocfdt04Np8Bs5hn9',
    'dQiaUqksbXOWmBPt2kBn0ARiVkr3r4mBwypQq',
    [203, 253, 155, 6, 148, 92, 81, 212]
  ],
  [
    'UuQ68x330IdojsLI',
    'pb6-OdmVdQ1gLP8E1szvlf0T6aOQp-EQHPW-tAKQ8Xj',
    [23, 158, 11, 26, 216, 251, 17, 229]
  ],
  [
    'T4ec6Q68QKiuIARL',
    'BeLjFIoODtDg5vLMLBN1Sae',
    [250, 103, 43, 65, 80, 229, 66, 116]
  ],
  [
    'xmZBUpwjJwnXZAp6',
    'WS2F3Nzg2s7TqVIygm8W1tQyNc6DFy',
    [186, 206, 177, 250, 182, 139, 138, 19]
  ],
  [
    '4qB6m0d_ryzb3w6q',
    '2Nr1sd1phWDB9gnuYOLUsjvX9jxntScWyRlX3Nj_xs8MV10LGgSgfRBKVGnO',
    [97, 101, 207, 79, 55, 205, 142, 253]
  ],
  [
    'SmVONU3BEODnkbdM',
    'G4WIU3UrBqbN6_nccFrIyx_TdXx-W80YzWw',
    [33, 147, 134, 20, 73, 169, 2, 107]
  ],
  [
    'zseM9_-0y7B9URxM',
    'us8B1DmHxOF10ue3jm2VfoJ250h364zRd2U8VIm2Lbkf3OWprSUpLF4ePjdj5aS',
    [80, 47, 98, 151, 139, 175, 78, 166]
  ],
  [
    'WY_sEWLFAybHSwX4',
    'vLJyXNkHCYGHWsvhXcU2sWYzgFYlWF7A_ZjFg8kJ4wwuJ',
    [132, 67, 168, 204, 90, 10, 169, 235]
  ],
  [
    'maWrEov1bBjSq2Zn',
    'sCP9zPakZ_wZ8hcQu-G6nN',
    [136, 204, 107, 221, 66, 198, 31, 201]
  ],
  [
    'tXInZHO-x4AWxKTp',
    'JQUM_O-E4-YI6dhxo',
    [36, 245, 166, 183, 31, 222, 192, 96]
  ],
  [
    'OqaQt_b1hvU-atC3',
    'X7Ou8cKo17xHlq_5gwM56GZrCSJBReeA60pDj2hUer6',
    [169, 107, 175, 79, 116, 24, 153, 93]
  ],
  ['nHdnXHGmGknC8FfC', 'cRupnAESNmU', [18, 200, 205, 81, 7, 32, 8, 213]],
  ['59n9lAJdrxIz3joe', 'WBPr', [75, 153, 152, 122, 242, 233, 165, 255]],
  [
    'q-PAAgkE9z2xed85',
    'AFOQD_H7MO3q3cxLa7TOUd89kpH03SpjpqmzY6AX16-uZFYcZZBb8D',
    [45, 4, 101, 133, 174, 99, 42, 4]
  ],
  [
    'tBzStZxn2ZqlQfBf',
    'nZdIaI7-bdqqh6aU7w4HfDCByX-x4_3q9Jf',
    [253, 49, 199, 224, 50, 253, 75, 144]
  ],
  [
    'rH8Nn75LyYC0hjVG',
    'IrDPpL-dkoh6VTy7pOtKKdAD9dLwUnE-',
    [76, 2, 97, 127, 190, 74, 74, 5]
  ],
  [
    'F-pI7AhpS1V-48eT',
    'Ao7hV41P08Zq4C1szyOVN7K1iWW8z',
    [121, 76, 85, 13, 162, 105, 174, 114]
  ],
  ['Khje_RmXXmJ3CAb1', 'TvMx3ISTfIQ', [237, 102, 92, 182, 242, 45, 27, 178]],
  [
    'G1KRzk-KMqCk-kbD',
    'imHZWdBz01lGR3m1zuO74berNn68uFZR3kcoWEaMhVjJ1g',
    [165, 3, 34, 126, 199, 101, 203, 184]
  ],
  [
    'wJhnTtBLcy_1rZay',
    'qbZ6oK0a4eWf2ud1sEnKLeguOmYsbG4aOTdlMdrf',
    [226, 169, 14, 147, 180, 88, 90, 132]
  ],
  [
    'vVl9fhjkwASu2WXe',
    '8-CjQylw18IKWgAL2mMxo',
    [30, 193, 202, 34, 74, 172, 72, 42]
  ],
  [
    'm2Qx2Dtbvwv3qjNJ',
    'WrIqIIsHqbgm3Qfg03QvaVG9G6fz2zxjnfNZUVuX8XUtjz4LQuj3VZNh',
    [237, 163, 64, 58, 187, 234, 117, 106]
  ],
  [
    '5R1maUgHiPQ0ZoaD',
    'SZJ6uMXnMuLll2xOfHcy_DE',
    [209, 26, 182, 131, 19, 180, 5, 55]
  ],
  [
    'dDBufcmObAK1dKYw',
    'ayjd0F5mqWsVF0MtUNJYo8S8GhuCsMCnEU6k3H9z0f8',
    [126, 244, 206, 245, 56, 4, 39, 63]
  ],
  [
    'o_YPVOjQ7Xw0G9OD',
    'UPF-HW1hJukwdVvhCl7IZJzy7a',
    [30, 211, 48, 214, 88, 189, 59, 33]
  ],
  [
    'oule-vFYlFJfsXU3',
    '8ORL7DUv28-yVfUw_cJ3imWP-iXrQRmzZRp0jtspwW_qm-rXmc1aBsbvbAut8',
    [66, 62, 243, 87, 153, 23, 230, 113]
  ],
  [
    'kEPlQxhC27GQcJeb',
    'wL-dAWvwZapITZZvgW46',
    [153, 83, 52, 252, 33, 23, 48, 216]
  ],
  [
    'GFilE6NpBPWE25uB',
    'RzoQCcd5NVeDbd2cx',
    [144, 101, 221, 104, 142, 244, 87, 216]
  ],
  ['sENqlFHs0NvkY28u', 'Gm2ojB-BJBdL', [75, 226, 42, 7, 94, 14, 215, 52]],
  ['mxiOr15qouOEhzHS', 'SChjLg6SXpEb9', [174, 64, 56, 79, 211, 158, 21, 229]],
  [
    'pFL_Sbx5RW0fuPHO',
    'hdb8HqaxEN99N4V1STTpnR4kr9F-lONwKp2TcOCopBFnDrjITz3jHPM4WKIYyw59US',
    [108, 66, 228, 165, 111, 142, 78, 201]
  ],
  [
    'sMgAXpCtVqeFm14R',
    'dNPnh6shnGYEZuN0id',
    [101, 147, 101, 20, 126, 33, 84, 255]
  ],
  [
    'nTu9mRGqYc1SOPk7',
    'ogL8VEqgoMkh6YNgTzvF4f87wHvmRhzncGPunN2ZJ5p3qUqZeJ3',
    [253, 16, 23, 144, 34, 207, 28, 82]
  ],
  ['d5jDH8Ppk82zj_vd', '5sfq9Q_0P0H', [197, 245, 4, 89, 247, 26, 240, 77]],
  [
    'bEEUPVwdHlYwYL6o',
    'AGoiVTE9foWm2MZqsn3dfS1XQiQW0QJwLXi6oXR2L9nMnPCPG_oF',
    [186, 203, 217, 87, 4, 177, 20, 242]
  ],
  [
    'JbKhWuTfRMWb4hFD',
    'NTNhYIahQ769TsCDwFyfOYZ8x6np58jg9hMAHFH-BMv7hBwESi596D4aDuyPabFGbqcG',
    [60, 79, 166, 97, 146, 213, 223, 59]
  ],
  [
    'hvCtw1q_GJUBFW_X',
    'uL5zgFM9WUTyO25dzVCmSVOxbpV70ZPurKK-CPUAmP',
    [127, 4, 233, 105, 7, 183, 123, 61]
  ],
  [
    'hWxh0P6EXlm4yYKA',
    'NUgrOoTOfqaB6JDZj',
    [96, 255, 249, 149, 117, 178, 189, 183]
  ],
  [
    'TLHDMak8qeH3ABaV',
    'HW-7PPunyMCinXt8QjQUuJUzZZQs1-T9ADR-6y',
    [46, 167, 85, 216, 34, 240, 131, 74]
  ],
  [
    'uE4OfzzqHVDH8lbd',
    '8KCUyGtkcG-T8gA3lpplC13LsnFZ',
    [18, 9, 33, 96, 47, 132, 243, 76]
  ],
  [
    'ocjA0Quge9vdCDbH',
    'tLlU03I9CDBbP1Pnl6KM3MW34TNzuuZYv0u-uU-l7RtFF0OmGoySyg_yc7vWswGkz',
    [124, 174, 227, 126, 197, 91, 232, 11]
  ],
  [
    'TDVmxGeyDULfxyrz',
    'A57Y0_L6K4TTzQx1-Yr1E6fVAZi31RyipeK0Q4uqwXXfRLo4tz2a5PSqN3-bdQ4f2',
    [53, 212, 137, 227, 12, 85, 50, 251]
  ],
  [
    '8OhqW3sA7s1vqEDr',
    'jlFquRWvL07TyLjW9ZNk81gxkvs4u1WLkNhOQVLOjFjw3iecMjun5Yk0xcruo',
    [147, 130, 134, 67, 235, 29, 115, 34]
  ],
  [
    '9kPcY6rfhPzSzEGn',
    'nS1kAxpsghzJJXiCzhNycDk2_EJ_yIT97fV2kxXTtfZ9p0',
    [178, 109, 176, 237, 184, 79, 209, 89]
  ],
  [
    'AJJ_yoEL8WyEtA1U',
    'vFNErhfCk1TZiTFMA6J8D',
    [26, 63, 142, 247, 30, 50, 167, 102]
  ],
  [
    'PBr4drRAJTaWv5Um',
    '5quc8Vd2rHVNk2NoDxk3TL',
    [150, 113, 209, 153, 101, 74, 42, 2]
  ],
  [
    'MnODoRJI2FgZrvLs',
    'gqJ_7HnrfiqYkenyvhe53SB1vTBgMiMB3kxF5',
    [205, 11, 216, 157, 130, 39, 60, 161]
  ],
  ['iSxQPJpp_s0ws-4b', 'K-J', [46, 78, 209, 241, 112, 90, 91, 181]],
  [
    'ZMm2tCGDJ04A3I_6',
    'gw-wcFYO1G2KEqJagWAic2l2d1FoTVXVT',
    [22, 60, 166, 216, 76, 146, 36, 22]
  ],
  [
    'Hxf6qsSIV6blPdB1',
    'GTWOerCQdUMkL6it6hEEPKBcOe_9f_B618ivjeM3BKfjzRQ8rvcGjUUJnsljerca6',
    [122, 74, 100, 36, 79, 173, 4, 91]
  ],
  [
    'U5gXdMrRYUdxuDjK',
    'siy9CxY2BbhazTqBWwFrtBLh',
    [79, 92, 248, 231, 189, 215, 27, 51]
  ],
  [
    'YJiK_B-TENJsVnd_',
    'Ohyz8XU06XWewcgTX-PffLVdatU3UFl6CYe',
    [22, 147, 91, 237, 188, 184, 70, 223]
  ],
  [
    'J7wVNfLdkCCtndH5',
    '1Vw163YqXwP8cPXIy5dSkcIoClBep7gWb0qGJzHM8h_hzk2GFtZyLKk',
    [123, 221, 220, 145, 75, 144, 103, 74]
  ],
  [
    'elId3b7ZyOg6HVif',
    'N89kQR7VMUgF4DyWhpTo_ZW2lERbNqFa1RdXjaUctO1FdevDAZaA',
    [39, 244, 17, 57, 240, 193, 34, 112]
  ],
  [
    'ydBueYO29jaUsEVU',
    'HMcnfvYjjz8Uf8bUhxXlAYHcyO7x5NHE_gc3bcWSMWJD2JdryrUBBdYj1',
    [252, 15, 32, 244, 143, 126, 130, 34]
  ],
  ['fVprx-PzTSx6CUcX', 'Q', [253, 22, 240, 135, 62, 55, 219, 1]],
  [
    '9ORMwecQjlob9aTT',
    '2cpq2XTWPk5sVLlN4OR5y6X_rTRFNUURgrwnWDg76u927cYud6PS-17UTgd3TO9g3K4',
    [15, 124, 108, 136, 56, 254, 85, 250]
  ],
  [
    '-V3BEGXuTWtFOMv4',
    '8l6qcZXfG9iSywi1IgwJ_PkZh0Bg2iR1cbGps_sWPdKXbIvDDX-3IeTTg',
    [111, 8, 18, 99, 6, 72, 56, 232]
  ],
  [
    'Cbvx4_KdboiNHs6P',
    'nzUo0UnqKn05adw5g0jtBN703bUgb8UxywfC93I7KN',
    [85, 17, 95, 157, 77, 25, 206, 45]
  ],
  [
    'SDPzfgeqkvmi62JH',
    'Z6kJuDD-8FSz1VwOuPeoSJ6X-4hpib563UjYxtFcB4SvhQr-Hstg5OhMi4iZZ',
    [153, 35, 172, 58, 141, 180, 95, 97]
  ],
  [
    'mBJlhP6D3M2raEjD',
    'ogtg66jr2KLCFO2RvodOXw0mt4XS6BOnLhBI_gDV0',
    [85, 231, 198, 97, 240, 108, 230, 150]
  ],
  [
    'Sz-mxKc7KGM7SDaf',
    'ecQ-7-3VddOdMSeKUbZE1t6Aa67pYGXjQeOckq1l50GkvfomFr',
    [18, 241, 24, 133, 142, 74, 218, 178]
  ],
  [
    '_5ck5scojT4oyJEq',
    '43oLkeixGHShTMUhtI',
    [35, 190, 107, 33, 2, 165, 11, 34]
  ],
  [
    '48ulC82W4qv49InN',
    '8HQyT55TtmGahy6w',
    [2, 70, 28, 124, 164, 101, 100, 185]
  ],
  ['-exgd5coAHqBu3ga', 'vRfqYthbUNh', [48, 188, 141, 96, 138, 114, 132, 143]],
  ['hJEBugObOX06pplH', 'oYYZ-v', [153, 112, 89, 5, 46, 138, 209, 254]],
  [
    'eSDsC63oTtVfi_F7',
    'BVmyPas409CmRHiRRiTPjJL87KgJefuDK6lEh5isghLl7l3a4Xmxa',
    [21, 198, 30, 251, 173, 36, 165, 82]
  ],
  [
    'KZtUPWMUr469RWL8',
    'F9K6TUd6j7Dm25rAS7cqOKDtSnnxj0hYKVTMFQ6CfA5218gPeZo',
    [203, 233, 183, 39, 57, 54, 60, 173]
  ],
  [
    '0TeBxGk-V7RPSZML',
    'kmL1fKqHwAoxI1b_ap8I9fGZMmcx3gIMiglxLLPFWOoDNUGe',
    [193, 7, 13, 148, 71, 231, 166, 135]
  ],
  [
    'PWYY82PNqwshPHiv',
    'Ya4LyHqxIxK8GaND9FIzqugleh-QELha_ntbRJixl6hZI5m3RfdrcntjiPJ',
    [27, 177, 64, 55, 129, 165, 132, 108]
  ],
  [
    'PtCub86vGwNj1tcv',
    'qR08eqAeNrrUYDl18C-wttqMDk',
    [66, 134, 247, 100, 38, 3, 7, 125]
  ],
  [
    '3eqQxzhNdv2kJqy5',
    '0wxAd9NT-Z8xFzomFwgMqMVbaUg',
    [36, 191, 165, 105, 211, 159, 155, 13]
  ],
  [
    'MgEjpTNPFFwes6Sm',
    '7SCVGNJYZhtnbiLZAE5TrsL5K1X',
    [208, 79, 201, 49, 48, 3, 227, 199]
  ],
  [
    'vSofRAYxXUU1qjhl',
    'HATE-YsASxySRkK5aJR4yV0mxx1YAuEgM5tUqyJDc7cLL',
    [61, 205, 183, 24, 68, 135, 7, 74]
  ],
  [
    'kIUe96sZ6LV464T_',
    'rjwrCOQAzLFbIM_3M7KfDQ1A6r3nkebk-dgqORG0Uy-n89_apYNLVTbdr3yuzXKOTfkRh',
    [83, 214, 143, 126, 145, 218, 225, 186]
  ],
  [
    '8wao85IcCu1mC-Rc',
    'AdVncBX6wkLXqMQPol3tNDPd5HJ',
    [161, 223, 243, 36, 219, 75, 215, 63]
  ],
  [
    'NRVNeO5wysG3DRuU',
    'Mr8vhiVPo5GpI6sho4R09k8D-vFgcghF3-kF',
    [246, 119, 57, 225, 254, 189, 182, 180]
  ],
  [
    'VHJZOECxfyxVyufk',
    'TMB3UMDEIs-vj_9aDBNDzT6HkHcwQQhr4EnG6A1AD9JkHENVAAQnS7s',
    [117, 85, 69, 116, 56, 27, 123, 62]
  ],
  [
    'TUfnTd3pmaJzSdD4',
    'VoRGCJgaGEhPSGRl0EPKWIzN7CRpD49CiyjC7y_4xRpppMNlR4v',
    [3, 116, 140, 4, 113, 208, 78, 186]
  ],
  [
    '-I1YgwmWxehyB6kv',
    'IplQLxea3JGywQn3XMNWrqVbE',
    [137, 251, 109, 201, 11, 101, 132, 97]
  ],
  [
    '4ic5nM5lbfMOXDRR',
    'TfVtpOoAQt1IxL0qJtAQoCJJThyxncIagOvKSpxjD7RDmh7YQBHWPkuv5lpSzpN',
    [192, 203, 84, 99, 85, 184, 122, 44]
  ],
  [
    'NYOq6hIu2C-aZPhE',
    'QQa0EWIHXqbrkq3nBeXt6yEj12z',
    [40, 199, 197, 21, 82, 53, 100, 58]
  ],
  [
    'nC93tajnfzk6bMtM',
    'p9gbEB4nMHXDqmOC413rI4Z',
    [200, 140, 102, 143, 89, 170, 219, 32]
  ],
  [
    'ZCCkYIbGOzXa5GRO',
    '2f9VGQeb4AtW6SwPjAGxxjyHNw3-MZj2BfxttNLxM0Tv_rpXO8TUH4YASb',
    [0, 174, 100, 194, 149, 35, 81, 12]
  ],
  [
    'oapO2W6hces4Pfkc',
    'oEyf5eqpM-N7LBp3C5vejvO7M87OzT4MHdwJz',
    [140, 195, 199, 20, 207, 60, 104, 240]
  ],
  [
    '__daPiDXrnPpS7eO',
    '1_tnhApr6nZbWIEPja0jAJ6LbTvD6oAEvPyrLYQ',
    [255, 244, 76, 119, 124, 124, 146, 214]
  ],
  [
    '5iIExqPt5W-ZpudD',
    'jNbLiDmQdN5X7HEOfgnAi5A7s1pGXwP41hX1Z',
    [149, 68, 125, 203, 174, 150, 66, 31]
  ],
  [
    'gD_J-R8tOb977BtL',
    'f7A81Qbh8gQhfRpOmtz5-ZJqBxiQJ6myBhGfqK7BVaGBL_W2MvfB',
    [106, 38, 140, 196, 141, 190, 232, 110]
  ],
  [
    'ZxHO4JJ8p45jTUXU',
    'fs4Oy8mPZS6919SZ7gDyKIILDkXnPt8SsXkfBd-Mnm4wO6alw-veQD9',
    [209, 53, 104, 100, 102, 136, 84, 134]
  ],
  [
    '2bVzT0moojGNQgIX',
    'nuyb-AgYY-rsmhtdav3LC7meSPy1dCosjSw0YAvgP',
    [1, 201, 247, 25, 104, 147, 148, 252]
  ],
  [
    'FicyyNT0BRua05i9',
    'TG4leSS_mcrZ_L68GKFdxc4-McFCCtdG7QpbPu_MolD5luE6n3dKlPzb9MvfvkiZKi',
    [136, 150, 66, 224, 178, 235, 114, 238]
  ],
  [
    'g5Qaf7mQAIxuHR0O',
    'A6u5gtb1yMSiGlWVt3exYsRS',
    [169, 20, 115, 32, 43, 71, 21, 193]
  ],
  [
    'aOACI6GP6u4WFyxp',
    '1eEx55L3E9MZga7l1WzpnKfI',
    [177, 26, 15, 27, 217, 101, 69, 195]
  ],
  ['Rr2jLg-asIQrlaRJ', 'rgALEbs', [163, 103, 250, 90, 4, 46, 69, 32]],
  [
    'p8qW0oYzj5zi55s5',
    'V1ZCoK73ifwcnzPjQEN7Q79MtZCskcpqiE3gfbqYPYRmy-q0lPxopkZZp2lNWKkpL_q5z',
    [29, 121, 240, 174, 51, 38, 238, 123]
  ],
  [
    'wA0cNUJOhIMpiopE',
    'U2RE2L2zZysyOTcsj5_JosVDaMRtUxkRWVCeBH0AeodMvYGBcHizhxc2QM89',
    [40, 230, 148, 164, 7, 168, 3, 46]
  ],
  [
    'zBCN1w4ypWCEfpwC',
    'VRcTwONsyRQIy2ymVniMmry',
    [184, 177, 56, 54, 152, 189, 120, 222]
  ],
  ['i8cumEDwOxSXT0gL', 'ifKav', [53, 190, 193, 228, 179, 41, 246, 171]],
  [
    'g3EswbaCSNMsegzm',
    'rTFnEuEDlwBB0Dw_q3-FUSaTCEjWe0pOPZDIWD35Us08Qa-nulc57YjDoGphUfBamq',
    [157, 64, 119, 179, 60, 147, 48, 17]
  ],
  [
    'iYsckWoQTk5ap8YO',
    'wIyTqa43-_GiZlHJ8UXcD_tnqKikH5DZUWxdQ1xjYMyzCr2JvKKRBm8BbcDl_Q8p',
    [96, 237, 170, 183, 48, 45, 116, 106]
  ],
  [
    'Iyk5MoAjoWq4n8bG',
    'IV2N5MC6kvk95ykEzb3jj0A7Sv0jjif45SR1avc0bRWot2aW',
    [99, 23, 149, 225, 242, 204, 47, 7]
  ],
  ['NfzdRXCegRRsHHYj', '5uLBPbyFQqiv', [136, 45, 110, 192, 36, 204, 171, 218]],
  [
    'YiJTXegVwaNDtlpl',
    'DbwKoF3CI5kd2JRKwfyuLpeGd6sFhqI0t43C2ph',
    [188, 126, 147, 191, 9, 114, 107, 60]
  ],
  ['ZuUlFM-yEzZ9XHKj', 'errecd71', [158, 231, 84, 47, 149, 227, 92, 111]],
  [
    'EtEXELa6V_NSjvEh',
    'yrTjrRuW8mJc3utw2JUH7iIW-J5vF3t9GC1-ZvRmO8UXNsG8-I3Iqgtinzoabqqbs1yvR',
    [186, 52, 144, 215, 104, 246, 174, 71]
  ],
  [
    'q2uA_VwMnaBtAgTx',
    'uJOymuDgBBS9Ec56JRGmKYsMHoGLCKA5wzwhtYf-g8-IT7UsAX1JHFGSV0EF',
    [176, 65, 188, 134, 212, 6, 97, 186]
  ],
  [
    '4RmqR10QiIZDDKNO',
    'oWY0Aj2CDCWuEFhdNHq2RFcGJD0sSRxK5K',
    [114, 28, 238, 228, 122, 40, 82, 13]
  ],
  [
    'a9DfUPCLyQ_yrNIa',
    '5G-6AVe7CBJl-NuuUN_7TN',
    [95, 206, 124, 185, 194, 207, 227, 111]
  ],
  ['8oB5yG87C2v5j0_4', '1S-aiUNRJ2c', [123, 42, 242, 79, 90, 36, 208, 81]],
  [
    'ZA2ZT22NXwD_UvTM',
    'UpV3pLYniWPm-PnWUAbBNeO4V-zuuw6IZQ1ZprLsC_LjGdSJP7rZCnoPz',
    [189, 209, 102, 128, 246, 141, 212, 109]
  ],
  [
    'ycz6aiuQFGKxZVsM',
    'fBuJp4_A_hiq--4uBhxjXfT3nRaYEJ8azW2_FKooXdSVRv2Y03VoWzPzG',
    [241, 127, 162, 199, 73, 10, 75, 24]
  ],
  [
    'eAmt0pClMyL8Sk69',
    'JFzXjfJhEMUCYEDrBKRM9OFFK0PSX',
    [176, 167, 43, 60, 16, 69, 194, 2]
  ],
  [
    'CTFnU2nwy9s1_kBj',
    'hEHqR0idFTzbvG193aLYj6y2DFPi2UKQut_A--43PdN1XF',
    [6, 84, 156, 248, 125, 55, 230, 121]
  ],
  ['CAhom0f872WEDXP6', 'dmX', [203, 98, 175, 172, 19, 3, 244, 177]],
  [
    'aON1dHrq90SbG8Hx',
    'v7LyiwuCrB7EgAibPve6Yg2gLmggxE6j7ocR37EudrH_P9XX2rQK',
    [147, 73, 50, 63, 71, 98, 203, 42]
  ]
]

test('crypto_shorthash', function (t) {
  const out = Buffer.alloc(sodium.crypto_shorthash_BYTES)
  const inp = Buffer.from('Hej, Verden!')
  const key = Buffer.alloc(sodium.crypto_shorthash_KEYBYTES)

  t.exception.all(function () {
    sodium.crypto_shorthash(Buffer.alloc(0), inp)
  }, 'throws on bad input')

  sodium.crypto_shorthash(out, inp, key)

  const result = '6a29984f782e684e'
  t.alike(out.toString('hex'), result, 'hashed the string')
})

test('constants', function (assert) {
  assert.ok(sodium.crypto_shorthash_PRIMITIVE)
  assert.ok(sodium.crypto_shorthash_KEYBYTES > 0)
  assert.ok(sodium.crypto_shorthash_BYTES > 0)
  assert.end()
})

test('crypto_shorthash fixtures', function (assert) {
  run(assert)
})

test('crypto_shorthash fixtures (wasm)', function (assert) {
  if (!sodium.crypto_shorthash_WASM_SUPPORTED) {
    assert.pass('wasm not supported')
    assert.end()
    return
  }

  assert.ok(sodium.crypto_shorthash_WASM_LOADED)
  run(assert)
})

function run(assert) {
  for (let i = 0; i < vectors.length; i++) {
    const v = vectors[i]
    const key = Buffer.from(v[0])
    const message = Buffer.from(v[1])
    const expected = Buffer.from(v[2])
    const out = Buffer.alloc(sodium.crypto_shorthash_BYTES)

    sodium.crypto_shorthash(out, message, key)
    if (Buffer.compare(out, expected) !== 0) {
      assert.fail('Failed on fixture #' + i)
      assert.end()
      return
    }
  }

  assert.pass('Passed all fixtures')
  assert.end()
}
