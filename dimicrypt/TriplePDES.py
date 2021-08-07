# Vasilis Dimitriadis - 2021
# Remember to donate to WCKDAWE <3
# DES Mode: ECB

import math
import multiprocessing as mp
import unittest

from .__helper import halve, merge
from .TripleDES import encrypt_triple_des, decrypt_triple_des, encrypt_triple_des_ecb, decrypt_triple_des_ecb
from .PDES import PDes
LEFT_SHIFTS = (1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28)


def _enc_ecb_helper(pdes_a: PDes, pdes_b: PDes, msg: int) -> int:
    return pdes_a.encrypt(
            pdes_b.decrypt(
                pdes_a.encrypt(msg),
            ),
           )


def _dec_ecb_helper(pdes_a: PDes, pdes_b: PDes, msg: int) -> str:
    dec = pdes_a.decrypt(
            pdes_b.encrypt(
                pdes_a.decrypt(msg),
            ),
          )
    return bytearray.fromhex(hex(dec)[2::]).decode('ascii')


class TriplePDes:
    def __init__(self, key):
        if isinstance(key, int):
            self.key = key
        elif isinstance(key, str):
            self.key = int(bytearray(key, encoding='ascii').hex(), 16)
        else:
            raise Exception('Unsupported key input')

        assert self.key < 2 ** 128, 'DES Key must be less than 128bits long'
        key_a, key_b = halve(self.key, 128)
        self.pdes_a = PDes(key_a)
        self.pdes_b = PDes(key_b)

    def encrypt(self, message: int) -> int:
        enc = self.pdes_a.encrypt(message)
        enc = self.pdes_b.decrypt(enc)
        return self.pdes_a.encrypt(enc)

    def decrypt(self, encrypted_message: int) -> int:
        dec = self.pdes_a.decrypt(encrypted_message)
        dec = self.pdes_b.encrypt(dec)
        return self.pdes_a.decrypt(dec)

    def encrypt_ecb(self, message: str) -> int:
        blocks_required = math.ceil(len(message) / 8)  # Calculate blocks required for ECB
        message = message.rjust(blocks_required * 8, chr(0))  # Right justify blocks (Padding)
        b = bytearray(message, encoding='ascii')  # Convert to bytearray

        blocks = [b[index: index + 8] for index in range(0, len(b), 8)]
        pool = mp.Pool(mp.cpu_count())
        enc_blocks = pool.starmap(_enc_ecb_helper, [(self.pdes_a, self.pdes_b, int(block.hex(), 16),) for block in blocks])
        pool.close()

        return merge(enc_blocks, 64)

    def decrypt_ecb(self, encrypted_message: int) -> str:
        encrypted_message = hex(encrypted_message)
        encrypted_message = encrypted_message[2::]
        enc_list = [encrypted_message[index: index + 16] for index in range(0, len(encrypted_message), 16)]

        pool = mp.Pool(mp.cpu_count())
        dec_str = pool.starmap(_dec_ecb_helper, [(self.pdes_a, self.pdes_b, int(enc, 16),) for enc in enc_list])
        pool.close()

        return ''.join(dec_str)


class TestTriplePDES(unittest.TestCase):
    def test_tutorial_encryption_match(self):
        M = 0x0123456789ABCDEF                  # Message
        K = 0x133457799BBCDFF1133457799BBCDFF2  # Key
        C = TriplePDes(K)
        enc_p = C.encrypt(M)
        enc = encrypt_triple_des(M, K)
        self.assertEqual(enc, enc_p)

    def test_tutorial_decryption_match(self):
        M = 0x85E813540F0AB405  # Message
        K = 0x133457799BBCDFF1133457799BBCDFF2  # Key
        C = TriplePDes(K)
        dec_p = C.decrypt(M)
        dec = decrypt_triple_des(M, K)
        self.assertEqual(dec, dec_p)

    def test_random_ecb_encryption_match(self):
        M = 'When the darkness prevails; ' \
            'when the moon stops shining; ' \
            'when you start to question your logic; ' \
            'when you start to question your profession; ' \
            'Remember; ' \
            'It was just a missing semicolon on line 42.'
        K = 'answer'
        C = TriplePDes(K)
        enc_p = C.encrypt_ecb(M)
        enc = encrypt_triple_des_ecb(M, K)
        self.assertEqual(enc, enc_p)

    def test_random_ecb_decryption_match(self):
        M = 0xE4AE7F5D387E5D019A9330FAFEC22CE1712F4A5F541F8E66E7177C2292C9B1AB7BD829611EEE3C807A421639C5430DFC6D5FB21A0EE5F36C401C700D11C4F5B7E4D1B3E858EC1B42CCD86750CE2E48618248911C4FBDA2BA8D0F062C4C73E146D871D9287C09F64DC19A1F394B465DC8C9768E0B2076528896E64F9849814FA0309DA403F18BD654154CA744DC72A6D6146A4524B991C458E51605F1D60F14C9AA3B08DFB7CF8F4FC5D8F4EE839E0C6D4AF3AFF59761352B1B79896C631C5AB6138AC091395E21E3
        K = 'answer'  # Key
        C = TriplePDes(K)
        dec_p = C.decrypt_ecb(M)
        dec = decrypt_triple_des_ecb(M, K)

        self.assertEqual(dec, dec_p)


if __name__ == '__main__':
    unittest.main(verbosity=2)
