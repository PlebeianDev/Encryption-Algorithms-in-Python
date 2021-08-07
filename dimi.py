from dimicrypt import encrypt_triple_des_ecb, decrypt_triple_des_ecb
from dimicrypt.PDES import subkey_generator as pdes_subkey_generator
from dimicrypt.DES import subkey_generator as des_subkey_generator
from timeit2 import ti2


if __name__ == '__main__':
    # ti2(
    #     des_subkey_generator,
    #     pdes_subkey_generator,
    #     args=[123],
    #     relative=True,
    # )
    r = pdes_subkey_generator(123)
    print(r)
    # pdes_subkey_generator(123)
    # des_subkey_generator(123)