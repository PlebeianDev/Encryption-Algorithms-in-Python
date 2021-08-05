# Vasilis Dimitriadis - 2021
# Algorithm / Tutorial used:    http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
# Bonus reading:                https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm
# Remember to donate to WCKDAWE <3

import unittest
from typing import Tuple

PC_1 = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)

PC_2 = (
    14,	17,	11,	24,	1,	5,
    3,	28,	15,	6,	21,	10,
    23,	19,	12,	4,	26,	8,
    16,	7,	27,	20,	13,	2,
    41,	52,	31,	37,	47,	55,
    30,	40,	51,	45,	33,	48,
    44,	49,	39,	56,	34,	53,
    46,	42,	50,	36,	29,	32,
)

IP = (
    58,	50,	42,	34,	26,	18,	10,	2,
    60,	52,	44,	36,	28,	20,	12,	4,
    62,	54,	46,	38,	30,	22,	14,	6,
    64,	56,	48,	40,	32,	24,	16,	8,
    57,	49,	41,	33,	25,	17,	9,	1,
    59,	51,	43,	35,	27,	19,	11,	3,
    61,	53,	45,	37,	29,	21,	13,	5,
    63,	55,	47,	39,	31,	23,	15,	7,
)

IP_REVERSE = (
    40,	8,	48,	16,	56,	24,	64,	32,
    39,	7,	47,	15,	55,	23,	63,	31,
    38,	6,	46,	14,	54,	22,	62,	30,
    37,	5,	45,	13,	53,	21,	61,	29,
    36,	4,	44,	12,	52,	20,	60,	28,
    35,	3,	43,	11,	51,	19,	59,	27,
    34,	2,	42,	10,	50,	18,	58,	26,
    33,	1,	41,	9,	49,	17,	57,	25,
)

E = (
    32,	1,	2,	3,	4,	5,
    4,	5,	6,	7,	8,	9,
    8,	9,	10,	11,	12,	13,
    12,	13,	14,	15,	16,	17,
    16,	17,	18,	19,	20,	21,
    20,	21,	22,	23,	24,	25,
    24,	25,	26,	27,	28,	29,
    28,	29,	30,	31,	32,	1,
)

LEFT_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

S1 = (
    [   14, 4,	13,	1,	2,	15,	11,	8,	3,	10,	6,	12,	5,	9,	0,	7   ],
    [   0,	15,	7,	4,	14,	2,	13,	1,	10,	6,	12,	11,	9,	5,	3,	8   ],
    [   4,	1,	14,	8,	13,	6,	2,	11,	15,	12,	9,	7,	3,	10,	5,	0   ],
    [   15,	12,	8,	2,	4,	9,	1,	7,	5,	11,	3,	14,	10,	0,	6,	13  ],
)

S2 = (
    [   15,	1,	8,	14,	6,	11,	3,	4,	9,	7,	2,	13,	12,	0,	5,	10  ],
    [   3,	13,	4,	7,	15,	2,	8,	14,	12,	0,	1,	10,	6,	9,	11,	5   ],
    [   0,	14,	7,	11,	10,	4,	13,	1,	5,	8,	12,	6,	9,	3,	2,	15  ],
    [   13,	8,	10,	1,	3,	15,	4,	2,	11,	6,	7,	12,	0,	5,	14,	9   ],
)

S3 = (
    [   10,	0,	9,	14,	6,	3,	15,	5,	1,	13,	12,	7,	11,	4,	2,	8   ],
    [   13,	7,	0,	9,	3,	4,	6,	10,	2,	8,	5,	14,	12,	11,	15,	1   ],
    [   13,	6,	4,	9,	8,	15,	3,	0,	11,	1,	2,	12,	5,	10,	14,	7   ],
    [   1,	10,	13,	0,	6,	9,	8,	7,	4,	15,	14,	3,	11,	5,	2,	12  ],
)

S4 = (
    [   7,	13,	14,	3,	0,	6,	9,	10,	1,	2,	8,	5,	11,	12,	4,	15  ],
    [   13,	8,	11,	5,	6,	15,	0,	3,	4,	7,	2,	12,	1,	10,	14,	9   ],
    [   10,	6,	9,	0,	12,	11,	7,	13,	15,	1,	3,	14,	5,	2,	8,	4   ],
    [   3,	15,	0,	6,	10,	1,	13,	8,	9,	4,	5,	11,	12,	7,	2,	14  ],
)

S5 = (
    [   2,	12,	4,	1,	7,	10,	11,	6,	8,	5,	3,	15,	13,	0,	14,	9   ],
    [   14,	11,	2,	12,	4,	7,	13,	1,	5,	0,	15,	10,	3,	9,	8,	6   ],
    [   4,	2,	1,	11,	10,	13,	7,	8,	15,	9,	12,	5,	6,	3,	0,	14  ],
    [   11,	8,	12,	7,	1,	14,	2,	13,	6,	15,	0,	9,	10,	4,	5,	3   ],
)

S6 = (
    [   12,	1,	10,	15,	9,	2,	6,	8,	0,	13,	3,	4,	14,	7,	5,	11  ],
    [   10,	15,	4,	2,	7,	12,	9,	5,	6,	1,	13,	14,	0,	11,	3,	8   ],
    [   9,	14,	15,	5,	2,	8,	12,	3,	7,	0,	4,	10,	1,	13,	11,	6   ],
    [   4,	3,	2,	12,	9,	5,	15,	10,	11,	14,	1,	7,	6,	0,	8,	13  ],
)

S7 = (
    [   4,	11,	2,	14,	15,	0,	8,	13,	3,	12,	9,	7,	5,	10,	6,	1   ],
    [   13,	0,	11,	7,	4,	9,	1,	10,	14,	3,	5,	12,	2,	15,	8,	6   ],
    [   1,	4,	11,	13,	12,	3,	7,	14,	10,	15,	6,	8,	0,	5,	9,	2   ],
    [   6,	11,	13,	8,	1,	4,	10,	7,	9,	5,	0,	15,	14,	2,	3,	12  ],
)

S8 = (
    [   13,	2,	8,	4,	6,	15,	11,	1,	10,	9,	3,	14,	5,	0,	12,	7   ],
    [   1,	15,	13,	8,	10,	3,	7,	4,	12,	5,	6,	11,	0,	14,	9,	2   ],
    [   7,	11,	4,	1,	9,	12,	14,	2,	0,	6,	10,	13,	15,	3,	5,	8   ],
    [   2,	1,	14,	7,	4,	10,	8,	13,	15,	12,	9,	0,	3,	5,	6,	11  ],
)

P = (
    16,	7,	20,	21,
    29,	12,	28,	17,
    1,	15,	23,	26,
    5,	18,	31,	10,
    2,	8,	24,	14,
    32,	27,	3,	9,
    19,	13,	30,	6,
    22,	11,	4,	25,
)


def left_circular_shift(inp, shift_length, inp_length):
    """https://stackoverflow.com/questions/63759207/circular-shift-of-a-bit-in-python-equivalent-of-fortrans-ishftc"""
    return ((inp << shift_length) % (1 << inp_length)) | (inp >> (inp_length - shift_length))


def subkey_generator(key) -> Tuple:
    K_plus = __permutate(key, PC_1, 64)

    # Split K_Plus into 2 parts, Cx and Dx
    Cx = [K_plus >> 28, ]         # Left Part
    Dx = [K_plus & 0xFFFFFFF, ]  # Right Part

    for i in range(1, 17):
        Cx.append(left_circular_shift(Cx[i-1], LEFT_SHIFTS[i-1], 28))
        Dx.append(left_circular_shift(Dx[i-1], LEFT_SHIFTS[i-1], 28))

    CxDx = []
    for i in range(0, 17):
        CxDx.append(__join_halves(Cx[i], Dx[i], 28))

    Kx = [None, ]
    for i in range(1, 17):
        Kx.append(__permutate(CxDx[i], PC_2, 56))

    return tuple(Kx)


def __permutate(inp, perm_table, bit_len) -> int:
    tmp = 0
    for index in perm_table:
        tmp <<= 1
        tmp |= (inp >> (bit_len - index) & 1)
    return tmp


def __halve(inp, bit_len) -> Tuple[int, int]:
    half_len = int(bit_len/2)
    return (inp >> half_len), (inp & (2**half_len - 1))


def __join_halves(left, right, bit_len) -> int:
    tmp = left << bit_len
    return tmp | right


def __split(inp, num, bit_len) -> tuple:
    tmp = []
    split_len = int(bit_len/num)
    mask = 2**split_len - 1
    for i in range(0, num):
        tmp.append(inp >> (bit_len - split_len*(i+1)) & mask)
    return tuple(tmp)


def __merge(inp_list: list, inp_bit_size) -> int:
    tmp = 0
    for inp in inp_list:
        tmp <<= inp_bit_size
        tmp |= inp

    return tmp


def __s_box(inp, table) -> int:
    r0 = inp >> 5 & 1  # inp >> (bit_len - split_len * (i + 1)) & mask)
    r1 = inp >> 0 & 1
    r = __join_halves(r0, r1, 1)
    c = inp >> 1 & 0xF

    return table[r][c]


def __f(r, k):
    er = __permutate(r, E, 32)
    ker = k ^ er
    Bn = __split(ker, 8, 48)
    Sn = [
        __s_box(Bn[0], S1), __s_box(Bn[1], S2), __s_box(Bn[2], S3), __s_box(Bn[3], S4),
        __s_box(Bn[4], S5), __s_box(Bn[5], S6), __s_box(Bn[6], S7), __s_box(Bn[7], S8),
    ]
    Sn_merged = __merge(Sn, 4)
    p = __permutate(Sn_merged, P, 32)
    return p


def encrypt(message: int, key: int) -> int:
    subkeys = subkey_generator(key)
    ip = __permutate(message, IP, 64)
    l0, r0 = __halve(ip, 64)

    Ln = [l0, ]
    Rn = [r0, ]
    for i in range(1, 17):
        Ln.append(Rn[i-1])
        Rn.append(Ln[i-1] ^ __f(Rn[i-1], subkeys[i]))

    R16L16 = __join_halves(Rn[16], Ln[16], 32)
    ip_rev = __permutate(R16L16, IP_REVERSE, 64)
    return ip_rev


class TestDES(unittest.TestCase):
    def test_tutorial_encryption_match(self):
        M = 0x0123456789ABCDEF  # Message
        K = 0x133457799BBCDFF1  # Key
        enc = encrypt(M, K)
        print(f'{enc:0x}')
        self.assertEqual(enc, 0x85E813540F0AB405)

    def test_random_encryption_match(self):
        # Demo using http://des.online-domain-tools.com/, Mode: ECB, Input & Key as HEX
        # Demo inputs & keys using: https://www.browserling.com/tools/random-hex
        MK_pairs = [
            [   0xD022BDF296E3D53B, 0x3858488EC480CF03  ],
            [   0xBE1507CEE975ACEF, 0x3A3EBD08F94C9AE6  ],
            [   0xF4222C97F8A54C6B, 0xCD3A821F13401A61  ],
            [   0xE76F93C3654E517C, 0xF6714D146A768660  ],
            [   0x789FC029DDD1D482, 0x43463E8FEEF69F6B  ],
        ]
        RESULTS = [
            0x3654573265339FA1,
            0x7D2F1008E5676027,
            0x8FB3D41F5BFFC7EE,
            0x5A83AC0054550014,
            0xE4308E8F8F5B604F,
        ]

        for pair_index, pair in enumerate(MK_pairs):
            enc = encrypt(pair[0], pair[1])
            self.assertEqual(enc, RESULTS[pair_index])


if __name__ == '__main__':
    unittest.main(verbosity=2)
