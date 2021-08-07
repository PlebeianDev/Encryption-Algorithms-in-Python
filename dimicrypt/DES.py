# Vasilis Dimitriadis - 2021
# Algorithm / Tutorial used:    http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
# Bonus reading:                https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm
# Remember to donate to WCKDAWE <3
# DES Mode: ECB
import math
import unittest
from typing import Tuple
from .__helper import halve, join_halves, split, merge, permutate

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
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
)

IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)

IP_REVERSE = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
)

E = (
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
)

LEFT_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

S1 = (
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
)

S2 = (
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
)

S3 = (
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
)

S4 = (
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
)

S5 = (
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
)

S6 = (
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
)

S7 = (
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
)

S8 = (
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
)

P = (
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
)


def left_circular_shift(inp, shift_length, inp_length):
    """https://stackoverflow.com/questions/63759207/circular-shift-of-a-bit-in-python-equivalent-of-fortrans-ishftc"""
    return ((inp << shift_length) % (1 << inp_length)) | (inp >> (inp_length - shift_length))


def subkey_generator(key) -> Tuple:
    K_plus = permutate(key, PC_1, 64)

    # Split K_Plus into 2 parts, Cx and Dx
    Cx = [K_plus >> 28, ]  # Left Part
    Dx = [K_plus & 0xFFFFFFF, ]  # Right Part

    for i in range(1, 17):
        Cx.append(left_circular_shift(Cx[i - 1], LEFT_SHIFTS[i - 1], 28))
        Dx.append(left_circular_shift(Dx[i - 1], LEFT_SHIFTS[i - 1], 28))

    CxDx = []
    for i in range(0, 17):
        CxDx.append(join_halves(Cx[i], Dx[i], 28))

    Kx = [None, ]
    for i in range(1, 17):
        Kx.append(permutate(CxDx[i], PC_2, 56))

    return tuple(Kx)


def __s_box(inp, table) -> int:
    r0 = inp >> 5 & 1  # inp >> (bit_len - split_len * (i + 1)) & mask)
    r1 = inp >> 0 & 1
    r = join_halves(r0, r1, 1)
    c = inp >> 1 & 0xF

    return table[r][c]


def __f(r, k):
    er = permutate(r, E, 32)
    ker = k ^ er
    Bn = split(ker, 8, 48)
    Sn = [
        __s_box(Bn[0], S1), __s_box(Bn[1], S2), __s_box(Bn[2], S3), __s_box(Bn[3], S4),
        __s_box(Bn[4], S5), __s_box(Bn[5], S6), __s_box(Bn[6], S7), __s_box(Bn[7], S8),
    ]
    Sn_merged = merge(Sn, 4)

    return permutate(Sn_merged, P, 32)


def __run_des(inp: int, subkeys: list) -> int:
    ip = permutate(inp, IP, 64)
    l0, r0 = halve(ip, 64)

    Ln = [l0, ]
    Rn = [r0, ]
    for i in range(1, 17):
        Ln.append(Rn[i - 1])
        Rn.append(Ln[i - 1] ^ __f(Rn[i - 1], subkeys[i]))

    R16L16 = join_halves(Rn[16], Ln[16], 32)

    return permutate(R16L16, IP_REVERSE, 64)


def encrypt_des(message: int, key: int) -> int:
    assert key < 2 ** 64, 'DES Key must be less than 64bits long'
    subkeys = list(subkey_generator(key))
    return __run_des(message, subkeys)


def encrypt_des_ecb(message: str, key: str) -> int:
    blocks_required = math.ceil(len(message) / 8)  # Calculate blocks required for ECB
    message = message.rjust(blocks_required * 8, chr(0))  # Right justify blocks (Padding)
    b = bytearray(message, encoding='ascii')  # Convert to bytearray
    k = bytearray(key, encoding='ascii')  # Convert to bytearray
    k = int(k.hex(), 16)  # String to int DES Key

    blocks = [b[index: index + 8] for index in range(0, len(b), 8)]
    enc_blocks = [encrypt_des(int(block.hex(), 16), k) for block in blocks]

    return merge(enc_blocks, 64)


def decrypt_des_ecb(encrypted_message: int, key: str) -> str:
    encrypted_message = hex(encrypted_message)
    encrypted_message = encrypted_message[2::]
    enc_list = [encrypted_message[index: index + 16] for index in range(0, len(encrypted_message), 16)]

    k = bytearray(key, encoding='ascii')  # Convert to bytearray
    k = int(k.hex(), 16)  # String to int DES Key

    dec_hex = [decrypt_des(int(enc, 16), k) for enc in enc_list]
    dec_str = [bytearray.fromhex(hex(dec)[2::]).decode('ascii') for dec in dec_hex]
    return ''.join(dec_str)


def decrypt_des(encrypted_message: int, key: int) -> int:
    assert key < 2 ** 64, 'DES Key must be less than 64bits long'
    subkeys = list(subkey_generator(key))
    subkeys.pop(0)
    subkeys.reverse()
    subkeys.insert(0, None)
    return __run_des(encrypted_message, subkeys)


class TestDES(unittest.TestCase):
    def test_tutorial_encryption_match(self):
        M = 0x0123456789ABCDEF  # Message
        K = 0x133457799BBCDFF1  # Key
        enc = encrypt_des(M, K)
        self.assertEqual(enc, 0x85E813540F0AB405)

    def test_tutorial_decryption_match(self):
        M = 0x85E813540F0AB405  # Message
        K = 0x133457799BBCDFF1  # Key
        dec = decrypt_des(M, K)
        self.assertEqual(dec, 0x0123456789ABCDEF)

    def test_random_encryption_match(self):
        # Demo using http://des.online-domain-tools.com/, Mode: ECB, Input & Key as HEX
        # Demo inputs & keys using: https://www.browserling.com/tools/random-hex
        MK_pairs = [
            [0xD022BDF296E3D53B, 0x3858488EC480CF03],
            [0xBE1507CEE975ACEF, 0x3A3EBD08F94C9AE6],
            [0xF4222C97F8A54C6B, 0xCD3A821F13401A61],
            [0xE76F93C3654E517C, 0xF6714D146A768660],
            [0x789FC029DDD1D482, 0x43463E8FEEF69F6B],
        ]
        RESULTS = [
            0x3654573265339FA1,
            0x7D2F1008E5676027,
            0x8FB3D41F5BFFC7EE,
            0x5A83AC0054550014,
            0xE4308E8F8F5B604F,
        ]

        for pair_index, pair in enumerate(MK_pairs):
            enc = encrypt_des(pair[0], pair[1])
            self.assertEqual(enc, RESULTS[pair_index])

    def test_random_decryption_match(self):
        # Demo using http://des.online-domain-tools.com/, Mode: ECB, Input & Key as HEX
        # Demo inputs & keys using: https://www.browserling.com/tools/random-hex
        MK_pairs = [
            [0x3654573265339FA1, 0x3858488EC480CF03],
            [0x7D2F1008E5676027, 0x3A3EBD08F94C9AE6],
            [0x8FB3D41F5BFFC7EE, 0xCD3A821F13401A61],
            [0x5A83AC0054550014, 0xF6714D146A768660],
            [0xE4308E8F8F5B604F, 0x43463E8FEEF69F6B],
        ]
        RESULTS = [
            0xD022BDF296E3D53B,
            0xBE1507CEE975ACEF,
            0xF4222C97F8A54C6B,
            0xE76F93C3654E517C,
            0x789FC029DDD1D482,
        ]

        for pair_index, pair in enumerate(MK_pairs):
            dec = decrypt_des(pair[0], pair[1])
            self.assertEqual(dec, RESULTS[pair_index])

    def test_random_ecb_encryption_match(self):
        enc = encrypt_des_ecb(
            message='When the darkness prevails; '
                    'when the moon stops shining; '
                    'when you start to question your logic; '
                    'when you start to question your profession; '
                    'Remember; '
                    'It was just a missing semicolon on line 42.',
            key='answer'
        )
        self.assertEqual(enc,
                         0xA1E366EE8E7140593CAC987CA58F170307C91516B1218A2D962C909F00198D13B7DCCC5A6B40E900EF1E6819FE6806852BFE559AD29A33FC09D30DF671F9A61A804EC66CDA42C3F3CC3EBA6031C5D27A36D1EB9DB0FB581F5F25A89488A467191B1176DB7B5899357C324056EEC98EC983F9F7B936D620E538AE84009DC74B4394728555B6C324C4F1C82D0FAF8052379897DF6FEB84F99140F57080929BE6EE42E9CE4F831378C5CAFD910DED54F0D2FD8B34EBB78955CB0E1A3096FB3CD4F28B6F0A8F5F1EB61D)

    def test_random_ecb_decryption_match(self):
        M = 0xA1E366EE8E7140593CAC987CA58F170307C91516B1218A2D962C909F00198D13B7DCCC5A6B40E900EF1E6819FE6806852BFE559AD29A33FC09D30DF671F9A61A804EC66CDA42C3F3CC3EBA6031C5D27A36D1EB9DB0FB581F5F25A89488A467191B1176DB7B5899357C324056EEC98EC983F9F7B936D620E538AE84009DC74B4394728555B6C324C4F1C82D0FAF8052379897DF6FEB84F99140F57080929BE6EE42E9CE4F831378C5CAFD910DED54F0D2FD8B34EBB78955CB0E1A3096FB3CD4F28B6F0A8F5F1EB61D
        K = 'answer'  # Key

        verify_message = 'When the darkness prevails; ' \
                         'when the moon stops shining; ' \
                         'when you start to question your logic; ' \
                         'when you start to question your profession; ' \
                         'Remember; ' \
                         'It was just a missing semicolon on line 42.' \

        dec = decrypt_des_ecb(M, K)
        print(verify_message)
        self.assertEqual(verify_message, dec)


if __name__ == '__main__':
    unittest.main(verbosity=2)
