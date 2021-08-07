# Vasilis Dimitriadis - 2021
# DES Parallelization paper:    https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.511.4739&rep=rep1&type=pdf
# Remember to donate to WCKDAWE <3
# DES Mode: ECB

# import unittest
import multiprocessing as mp
from typing import Tuple
from .__helper import halve, join_halves, split, merge, permutate
from .DES import IP, IP_REVERSE, PC_1, PC_2, LEFT_SHIFTS, E, P, S1, S2, S3, S4, S5, S6, S7, S8


def left_circular_shift(inp, shift_length, inp_length):
    """https://stackoverflow.com/questions/63759207/circular-shift-of-a-bit-in-python-equivalent-of-fortrans-ishftc"""
    return ((inp << shift_length) % (1 << inp_length)) | (inp >> (inp_length - shift_length))


def subkey_generator(key) -> Tuple:
    K_plus = permutate(key, PC_1, 64)

    # Split K_Plus into 2 parts, Cx and Dx
    Cx = [K_plus >> 28, ]         # Left Part
    Dx = [K_plus & 0xFFFFFFF, ]  # Right Part

    for i in range(1, 17):
        Cx.append(left_circular_shift(Cx[i-1], LEFT_SHIFTS[i-1], 28))
        Dx.append(left_circular_shift(Dx[i-1], LEFT_SHIFTS[i-1], 28))

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


def encrypt(message: int, key: int) -> int:
    subkeys = list(subkey_generator(key))
    return __run_des(message, subkeys)


def decrypt(encrypted_message: int, key: int) -> int:
    subkeys = list(subkey_generator(key))
    subkeys.pop(0)
    subkeys.reverse()
    subkeys.insert(0, None)
    return __run_des(encrypted_message, subkeys)


if __name__ == '__main__':
    # unittest.main(verbosity=2)
    pass
