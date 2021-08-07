# Vasilis Dimitriadis - 2021
# Algorithm / Tutorial used:    http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
# Bonus reading:                https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm
# Remember to donate to WCKDAWE <3
# DES Mode: ECB
import math
import unittest
from .DES import encrypt_des, decrypt_des
from .__helper import halve, merge


def encrypt_triple_des(message: int, key: int) -> int:
    assert key < 2 ** 128, 'DES Key must be less than 128bits long'
    key_a, key_b = halve(key, 128)

    enc = encrypt_des(message, key_a)
    enc = decrypt_des(enc, key_b)
    return encrypt_des(enc, key_a)


def decrypt_triple_des(encrypted_message: int, key: int) -> int:
    assert key < 2 ** 128, 'DES Key must be less than 128bits long'
    key_a, key_b = halve(key, 128)

    dec = decrypt_des(encrypted_message, key_a)
    dec = encrypt_des(dec, key_b)
    return decrypt_des(dec, key_a)


def encrypt_triple_des_ecb(message: str, key: str) -> int:
    blocks_required = math.ceil(len(message) / 8)  # Calculate blocks required for ECB
    message = message.rjust(blocks_required * 8, chr(0))  # Right justify blocks (Padding)
    b = bytearray(message, encoding='ascii')  # Convert to bytearray
    k = bytearray(key, encoding='ascii')  # Convert to bytearray
    k = int(k.hex(), 16)  # String to int DES Key
    key_a, key_b = halve(k, 128)

    blocks = [b[index: index + 8] for index in range(0, len(b), 8)]
    enc_blocks = [
        encrypt_des(
            decrypt_des(
                encrypt_des(int(block.hex(), 16), key_a),
                key_b
            ),
            key_a
        )
        for block in blocks
    ]

    return merge(enc_blocks, 64)


def decrypt_triple_des_ecb(encrypted_message: int, key: str) -> str:
    encrypted_message = hex(encrypted_message)
    encrypted_message = encrypted_message[2::]
    enc_list = [encrypted_message[index: index + 16] for index in range(0, len(encrypted_message), 16)]

    k = bytearray(key, encoding='ascii')  # Convert to bytearray
    k = int(k.hex(), 16)  # String to int DES Key
    key_a, key_b = halve(k, 128)

    dec_hex = [
        decrypt_des(
            encrypt_des(
                decrypt_des(int(enc, 16), key_a),
                key_b
            ),
            key_a
        )

        for enc in enc_list
    ]

    dec_str = [bytearray.fromhex(hex(dec)[2::]).decode('ascii') for dec in dec_hex]
    return ''.join(dec_str)


class TestTripleDES(unittest.TestCase):
    def test_tutorial_encryption_match(self):
        M = 0x0123456789ABCDEF                      # Message
        K = 0x133457799BBCDFF1133457799BBCDFF2      # Key
        enc = encrypt_triple_des(M, K)
        self.assertEqual(enc, 0x013FB83C9A4ECFF4)

    def test_tutorial_decryption_match(self):
        M = 0x013FB83C9A4ECFF4                      # Message
        K = 0x133457799BBCDFF1133457799BBCDFF2      # Key
        dec = decrypt_triple_des(M, K)
        self.assertEqual(dec, 0x0123456789ABCDEF)

    def test_random_encryption_match(self):
        # Demo using http://des.online-domain-tools.com/, Mode: ECB, Input & Key as HEX
        # Demo inputs & keys using: https://www.browserling.com/tools/random-hex
        MK_pairs = [
            [0xD022BDF296E3D53B, 0x3A3EBD08F94C9AE63858488EC480CF03],
            [0xBE1507CEE975ACEF, 0x3858488EC480CF033A3EBD08F94C9AE6],
            [0xF4222C97F8A54C6B, 0xCD3A821F13401A613858488EC480CF03],
        ]
        RESULTS = [
            0x64BF0E9477B8DA60,
            0xD4F4D34BC5505426,
            0x308919DE5E07BFDE,
        ]

        for pair_index, pair in enumerate(MK_pairs):
            enc = encrypt_triple_des(pair[0], pair[1])
            self.assertEqual(enc, RESULTS[pair_index])

    def test_random_decryption_match(self):
        # Demo using http://des.online-domain-tools.com/, Mode: ECB, Input & Key as HEX
        # Demo inputs & keys using: https://www.browserling.com/tools/random-hex
        MK_pairs = [
            [0x64BF0E9477B8DA60, 0x3A3EBD08F94C9AE63858488EC480CF03],
            [0xD4F4D34BC5505426, 0x3858488EC480CF033A3EBD08F94C9AE6],
            [0x308919DE5E07BFDE, 0xCD3A821F13401A613858488EC480CF03],
        ]
        RESULTS = [
            0xD022BDF296E3D53B,
            0xBE1507CEE975ACEF,
            0xF4222C97F8A54C6B,
        ]

        for pair_index, pair in enumerate(MK_pairs):
            dec = decrypt_triple_des(pair[0], pair[1])
            self.assertEqual(dec, RESULTS[pair_index])

    def test_random_ecb_encryption_match(self):
        enc = encrypt_triple_des_ecb(
            message='When the darkness prevails; '
                    'when the moon stops shining; '
                    'when you start to question your logic; '
                    'when you start to question your profession; '
                    'Remember; '
                    'It was just a missing semicolon on line 42.',
            key='answer'
        )
        self.assertEqual(enc,
                         0xE4AE7F5D387E5D019A9330FAFEC22CE1712F4A5F541F8E66E7177C2292C9B1AB7BD829611EEE3C807A421639C5430DFC6D5FB21A0EE5F36C401C700D11C4F5B7E4D1B3E858EC1B42CCD86750CE2E48618248911C4FBDA2BA8D0F062C4C73E146D871D9287C09F64DC19A1F394B465DC8C9768E0B2076528896E64F9849814FA0309DA403F18BD654154CA744DC72A6D6146A4524B991C458E51605F1D60F14C9AA3B08DFB7CF8F4FC5D8F4EE839E0C6D4AF3AFF59761352B1B79896C631C5AB6138AC091395E21E3)

    def test_random_ecb_decryption_match(self):
        M = 0xE4AE7F5D387E5D019A9330FAFEC22CE1712F4A5F541F8E66E7177C2292C9B1AB7BD829611EEE3C807A421639C5430DFC6D5FB21A0EE5F36C401C700D11C4F5B7E4D1B3E858EC1B42CCD86750CE2E48618248911C4FBDA2BA8D0F062C4C73E146D871D9287C09F64DC19A1F394B465DC8C9768E0B2076528896E64F9849814FA0309DA403F18BD654154CA744DC72A6D6146A4524B991C458E51605F1D60F14C9AA3B08DFB7CF8F4FC5D8F4EE839E0C6D4AF3AFF59761352B1B79896C631C5AB6138AC091395E21E3
        K = 'answer'  # Key

        verify_message = 'When the darkness prevails; ' \
                         'when the moon stops shining; ' \
                         'when you start to question your logic; ' \
                         'when you start to question your profession; ' \
                         'Remember; ' \
                         'It was just a missing semicolon on line 42.' \

        dec = decrypt_triple_des_ecb(M, K)
        self.assertEqual(verify_message, dec)


if __name__ == '__main__':
    unittest.main(verbosity=2)
