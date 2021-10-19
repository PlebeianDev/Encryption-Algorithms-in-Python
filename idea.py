# Modules
import random


# Constants
uint16_mask = (1<<16)-1


# Arithmetic Funcs
def iter_blocks(seq, blocksize):
    for i in range(0, len(seq), blocksize):
        yield seq[i:i+blocksize]

def hexstr_to_bytes(hexstr):
    return bytes(int(i, 16) for i in iter_blocks(hexstr, 2))

def add(x, y):
    return (x+y)&uint16_mask

def mul(x, y):
    if x == 0x0000:
        x = 0x10000
    if y == 0x0000:
        y = 0x10000
    res = (x*y)%0x10001
    if res == 0x10000:
        res = 0x0000
    return res

def add_inverse(x):
    # Returs additive inverse of invert key schedule
    return (-x)&uint16_mask

def mul_inverse(x):
    # multiplicative inverse 
    if x == 0:
        return 0;
    else:
        return pow(x, 0xFFFF, 0x10001)


# Encryption funcs
def encrypt(block, key):
    return idea(block, key, "encrypt")

def decrypt(block, key):
    return idea(block, key, "decrypt")

def expand_key_schedule(key):
    # keybytes into uint128 key
    big_key = int.from_bytes(key, "big")
    # Append 16bit prefix for uint144
    big_key = (big_key<<16) | (big_key>>112)
    # Extract 16 bits at diff offsets from schedule
    res = []
    tmp = None
    for i in range(8*6+4):  # 8 rounds, 6 subkeys, 4 keys for output transformation
        offset = (i*16+i // 8*25)%128
        tmp = (big_key>>(128-offset)) & uint16_mask
        res.append(tmp)
    return res

def invert_key_schedule(key):
    res = []
    res.append(mul_inverse(key[-4]))
    res.append(add_inverse(key[-3]))
    res.append(add_inverse(key[-2]))
    res.append(mul_inverse(key[-1]))
    res.append(key[-6])
    res.append(key[-5])

    for i in range(1, 8):
        j = i*6
        res.append(mul_inverse(key[-j-4]))
        res.append(add_inverse(key[-j-2]))
        res.append(add_inverse(key[-j-3]))
        res.append(mul_inverse(key[-j-1]))
        res.append(key[-j-6])
        res.append(key[-j-5])
    
    res.append(mul_inverse(key[0]))
    res.append(add_inverse(key[1]))
    res.append(add_inverse(key[2]))
    res.append(mul_inverse(key[3]))

    return res

def idea(block, key, operation):
    # Encrypts a block(of the key). From 16 bytes to 8.
    key_schedule = expand_key_schedule(key)
    if operation == "decrypt":
        key_schedule = invert_key_schedule(key_schedule)
    
    # Make blocks
    a = int.from_bytes(block[0:2], "big")
    b = int.from_bytes(block[2:4], "big")
    c = int.from_bytes(block[4:6], "big")
    d = int.from_bytes(block[6:8], "big")

    # Perform encryption in 8 rounds
    for i in range(8):
        j = i*6

        a = mul(a, key_schedule[j])
        b = add(b, key_schedule[j+1])
        c = add(c, key_schedule[j+2])
        d = mul(d, key_schedule[j+3])
        e = mul(a^c, key_schedule[j+4])
        f = mul(add(b^d, e), key_schedule[j+5])
        e = add(e, f)
        
        a ^= f  # bit XOR
        b ^= e
        c ^= f
        d ^= e
        a,b = b,a
    
    # Remaining round
    a,b = b,a
    a = mul(a, key_schedule[-4])
    b = add(b, key_schedule[-3])
    c = add(c, key_schedule[-2])
    d = mul(d, key_schedule[-1])

    return a.to_bytes(2, "big") + b.to_bytes(2, "big") + c.to_bytes(2, "big") + d.to_bytes(2, "big")


def main():
    msg = "000102030405060708090A0B0C0D0E0F"
    key = "DB2D4A92AA68273F"
    expected_enc = "0011223344556677"

    key_bin = hexstr_to_bytes(key)
    msg_bin = hexstr_to_bytes(msg)
    exp_bin = hexstr_to_bytes(expected_enc)

    print("key_bin -> hex: " + str(key_bin.hex()))
    print("msg_bin -> hex: " + str(msg_bin.hex()))
    print("expected enc result: " + str(exp_bin.hex()))

    enc = encrypt(msg_bin, key_bin)
    print("enc result: " + str(enc.hex()))

    dec = decrypt(enc, key_bin)
    print("dec result: " + str(dec.hex()))


if __name__ == "__main__":
    main()

