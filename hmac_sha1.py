# Libraries / Modules
import hashlib


# Functions
def xor(a, b):
    return bytes(a[i] ^ b[i] for i in range(min(len(a), len(b))))

def hmac_sha1(key, msg):
    # Will use hashlibs sha1 function for hashing, same can be applied with any hashing algorithm
    
    # Keys >64 are hashed
    if len(key) > 64:
        key = hashlib.sha1(key)
    # Keys <64 are padded with 0
    if len(key) < 64:
        key = key + b'\x00' * (64 - len(key))
    
    inner_pad = b'\x36' * 64  # algorithm dictates 36 and 5c
    outer_pad = b'\x5c' * 64 

    inner_pkey = hashlib.sha1(xor(key, inner_pad))
    inner_pkey.update(msg)
    outer_pkey = hashlib.sha1(xor(key, outer_pad))
    outer_pkey.update(inner_pkey.digest())

    return outer_pkey.digest()

def main():
    msg = input("Give string to encrypt: \n")
    key = input("Give encryption key: \n")

    msg = bytes(msg, 'utf-8')  # convert to bytes
    key = bytes(key, 'utf-8')

    res = hmac_sha1(key, msg)
    print(res.hex())

def test1():
    # Test for hmac-sha1 provided by https://datatracker.ietf.org/doc/html/rfc2202
    key = 'Jefe'
    msg = 'what do ya want for nothing?'
    msg = bytes(msg, 'utf-8')  # convert to bytes
    key = bytes(key, 'utf-8')
    # Result should be effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
    res = hmac_sha1(key, msg)
    print(res.hex())

def test2():
    # Test for hmac-sha1 provided by https://en.wikipedia.org/wiki/HMAC
    key = 'key'
    msg = 'The quick brown fox jumps over the lazy dog'
    msg = bytes(msg, 'utf-8')  # convert to bytes
    key = bytes(key, 'utf-8')
    # Result should be de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
    res = hmac_sha1(key, msg)
    print(res.hex())

if __name__ == "__main__":
    # test1()
    # test2()
    main()