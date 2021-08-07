# Vasilis Dimitriadis | 2021 | ICB.SCI.UTH.GR |
# Course: Software Design & Development
# ------------------------------------------------------------------
# Demo displaying my incompetence to create a parallel DES algorithm
# that is actually worth it.
# Encryption algorithms usually do not benefit from parallelism due
# to their design nature. Parts that can be parallel are either too
# small or inexpensive functions. Usually multi-core message exchange
# takes more time than these functions.

import time
from dimicrypt import encrypt_des_ecb, decrypt_des_ecb, PDes

if __name__ == '__main__':
    start = time.time()
    res = encrypt_des_ecb('Just an encrypted message', 'akey')
    end = time.time()
    print(f'Non-parallel encryption: {(end - start):0.32f}s to generate: {res}')

    start = time.time()
    res = decrypt_des_ecb(res, 'akey')
    end = time.time()
    print(f'Non-parallel decryption: {(end - start):0.32f}s to generate: {res}')

    start = time.time()
    pdes = PDes('akey')
    res = pdes.encrypt_ecb('Just an encrypted message')
    end = time.time()
    print(f'Parallel encryption: {(end - start):0.32f}s to generate: {res}')

    start = time.time()
    pdes = PDes('akey')
    res = pdes.decrypt_ecb(res)
    end = time.time()
    print(f'Parallel decryption: {(end - start):0.32f}s to generate: {res}')


