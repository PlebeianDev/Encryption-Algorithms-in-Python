# Vasilis Dimitriadis - 2021
# DES Parallelization paper:    https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.511.4739&rep=rep1&type=pdf
# Remember to donate to WCKDAWE <3
# DES Mode: ECB

import math
import multiprocessing as mp
import unittest
from typing import Tuple
from .__helper import halve, join_halves, permutate, left_circular_shift, merge
from .DES import IP, IP_REVERSE, PC_1, PC_2, __f, encrypt_des, decrypt_des, encrypt_des_ecb, decrypt_des_ecb

LEFT_SHIFTS = (1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28)


def _run_des(inp: int, subkeys: list) -> int:
    ip = permutate(inp, IP, 64)
    l0, r0 = halve(ip, 64)

    Ln = [l0, ]
    Rn = [r0, ]
    for i in range(1, 17):
        Ln.append(Rn[i - 1])
        Rn.append(Ln[i - 1] ^ __f(Rn[i - 1], subkeys[i - 1]))

    R16L16 = join_halves(Rn[16], Ln[16], 32)

    return permutate(R16L16, IP_REVERSE, 64)


class PDes:
    def __init__(self, key):
        if isinstance(key, int):
            self.key = key
        elif isinstance(key, str):
            self.key = int(bytearray(key, encoding='ascii').hex(), 16)
        else:
            raise Exception('Unsupported key input')

        assert self.key < 2 ** 64, 'DES Key must be less than 64bits long'
        self.subkeys = list(self.subkey_generator(self.key))

    @staticmethod
    def subkey_generator(key: int) -> Tuple:
        K_plus = permutate(key, PC_1, 64)

        # Split K_Plus into 2 parts, C0 and D0
        C0 = K_plus >> 28  # Left Part
        D0 = K_plus & 0xFFFFFFF  # Right Part

        pool = mp.Pool(mp.cpu_count())
        Cx = pool.starmap(left_circular_shift, [(C0, shift, 28) for shift in LEFT_SHIFTS])
        Dx = pool.starmap(left_circular_shift, [(D0, shift, 28) for shift in LEFT_SHIFTS])
        CxDx = pool.starmap(join_halves, [(Cx[i], Dx[i], 28) for i in range(0, 16)])
        Kx = pool.starmap(permutate, [(CxDx[i], PC_2, 56) for i in range(0, 16)])
        pool.close()

        return tuple(Kx)

    def encrypt_pdes(self, message: int) -> int:
        return _run_des(message, self.subkeys)

    def decrypt_pdes(self, encrypted_message: int) -> int:
        return _run_des(encrypted_message, list(reversed(self.subkeys)))

    def encrypt_pdes_ecb(self, message: str) -> int:
        blocks_required = math.ceil(len(message) / 8)  # Calculate blocks required for ECB
        message = message.rjust(blocks_required * 8, chr(0))  # Right justify blocks (Padding)
        b = bytearray(message, encoding='ascii')  # Convert to bytearray

        pool = mp.Pool(mp.cpu_count())
        blocks = [b[index: index + 8] for index in range(0, len(b), 8)]
        enc_blocks = pool.starmap(self.encrypt_pdes, [(int(block.hex(), 16), ) for block in blocks])
        pool.close()

        return merge(enc_blocks, 64)

    def decrypt_pdes_ecb(self, encrypted_message: int) -> str:
        encrypted_message = hex(encrypted_message)
        encrypted_message = encrypted_message[2::]
        enc_list = [encrypted_message[index: index + 16] for index in range(0, len(encrypted_message), 16)]

        pool = mp.Pool(mp.cpu_count())
        dec_hex = pool.starmap(self.decrypt_pdes, [(int(enc, 16),) for enc in enc_list])
        dec_tmp = pool.starmap(bytearray.fromhex, [(hex(dec)[2::],) for dec in dec_hex])
        dec_str = [dec.decode('ascii') for dec in dec_tmp]
        pool.close()
        return ''.join(dec_str)


class TestPDES(unittest.TestCase):
    def test_tutorial_encryption_match(self):
        M = 0x0123456789ABCDEF  # Message
        K = 0x133457799BBCDFF1  # Key
        C = PDes(K)
        enc_p = C.encrypt_pdes(M)
        enc = encrypt_des(M, K)
        self.assertEqual(enc, enc_p)

    def test_tutorial_decryption_match(self):
        M = 0x85E813540F0AB405  # Message
        K = 0x133457799BBCDFF1  # Key
        C = PDes(K)
        dec_p = C.decrypt_pdes(M)
        dec = decrypt_des(M, K)
        self.assertEqual(dec, dec_p)

    def test_random_ecb_encryption_match(self):
        M = 'When the darkness prevails; ' \
            'when the moon stops shining; ' \
            'when you start to question your logic; ' \
            'when you start to question your profession; ' \
            'Remember; ' \
            'It was just a missing semicolon on line 42.'
        K = 'answer'
        C = PDes(K)
        enc_p = C.encrypt_pdes_ecb(M)
        enc = encrypt_des_ecb(M, K)
        self.assertEqual(enc, enc_p)

    def test_random_ecb_decryption_match(self):
        M = 0xA1E366EE8E7140593CAC987CA58F170307C91516B1218A2D962C909F00198D13B7DCCC5A6B40E900EF1E6819FE6806852BFE559AD29A33FC09D30DF671F9A61A804EC66CDA42C3F3CC3EBA6031C5D27A36D1EB9DB0FB581F5F25A89488A467191B1176DB7B5899357C324056EEC98EC983F9F7B936D620E538AE84009DC74B4394728555B6C324C4F1C82D0FAF8052379897DF6FEB84F99140F57080929BE6EE42E9CE4F831378C5CAFD910DED54F0D2FD8B34EBB78955CB0E1A3096FB3CD4F28B6F0A8F5F1EB61D
        K = 'answer'  # Key
        C = PDes(K)
        dec_p = C.decrypt_pdes_ecb(M)
        dec = decrypt_des_ecb(M, K)
        self.assertEqual(dec, dec_p)


if __name__ == '__main__':
    unittest.main(verbosity=2)