# Vasilis Dimitriadis - 2021
# Algorithm / Tutorial used:    http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
# Bonus reading:                https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm
# Remember to donate to WCKDAWE <3
# DES Mode: ECB

import unittest
from .DES import encrypt_des, decrypt_des
from .__helper import halve


def encrypt_triple_des(message: int, key: int) -> int:
    key_a, key_b = halve(key, 128)

    enc = encrypt_des(message, key_a)
    enc = decrypt_des(enc, key_b)
    return encrypt_des(enc, key_a)


def decrypt_triple_des(encrypted_message: int, key: int) -> int:
    key_a, key_b = halve(key, 128)

    dec = decrypt_des(encrypted_message, key_a)
    dec = encrypt_des(dec, key_b)
    return decrypt_des(dec, key_a)


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
