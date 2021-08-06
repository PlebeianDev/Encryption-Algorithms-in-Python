import multiprocessing as mp
from timeit2 import ti2
from dimicrypt import encrypt_des, decrypt_des, encrypt_triple_des, decrypt_triple_des

if __name__ == '__main__':
    M = 0x64BF0E9477B8DA60
    K = 0x3A3EBD08F94C9AE63858488EC480CF03
    enc = encrypt_des(M, K)
    dec = decrypt_des(enc, K)

    print(f'M\t\t: {M:016X}')
    print(f'K\t\t: {K:032X}')
    print(f'ENC\t\t: {enc:016X}')
    print(f'DEC\t\t: {dec:016X}')

    print("Number of processors: ", mp.cpu_count())
    ti2(
        encrypt_des,
        encrypt_triple_des,
        args=[M, K],
    )
    ti2(
        decrypt_des,
        decrypt_triple_des,
        args=[enc, K],
    )
