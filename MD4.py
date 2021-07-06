import struct
import math
import hashlib

def F(x, y, z):
    return (x & y) | (~x & z)

def G(x, y, z):
    return (x & y) | (x & z) | (y & z)

def H(x, y, z):
    return x ^ y ^ z


def leftRotation(value, n):
    leftbits, rightbits = (value << n) & 0xFFFFFFFF, value >> (32 - n)
    return leftbits | rightbits



def MD4(word):
    padded_word = bytes(word.encode())


    rn = (-(len(word) + 8) % 64) -1 # reverse mod so we can skip the while loop  => value = 64 - (number mod 64) 

    padded_word += b"\x80"
    padded_word += b"\x00" * rn
    n = int((len(word) * 8) % math.pow(2, 64))


    padded_word += struct.pack("<Q" ,n)



    chunks = [padded_word[i:i + 64]for i in range(0, len(padded_word), 64)] #split padded_word in 64 bits words

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476 
    h = []
    h0 = [a0, b0, c0, d0]

    for chunk in chunks:
        X = list( struct.unpack("<16I", chunk) )
    
        h = h0.copy()

        # Round 1.
        Xi = [3, 7, 11, 19]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = n, Xi[n % 4]
            hn = h[i] + F(h[j], h[k], h[l]) + X[K]
            h[i] = leftRotation(hn & 0xFFFFFFFF, S)

        # Round 2.
        Xi = [3, 5, 9, 13]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = n % 4 * 4 + n // 4, Xi[n % 4]
            hn = h[i] + G(h[j], h[k], h[l]) + X[K] + 0x5A827999
            h[i] = leftRotation(hn & 0xFFFFFFFF, S)

        # Round 3.
        Xi = [3, 9, 11, 15]
        Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = Ki[n], Xi[n % 4]
            hn = h[i] + H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
            h[i] = leftRotation(hn & 0xFFFFFFFF, S)
        tempH = h
        h = [((v + n) & 0xFFFFFFFF) for v, n in zip(h, h0)]
        h0 = tempH
    result = struct.pack("<4L", *h)
    formated_result = "".join(f"{value:02x}" for value in result)
    return formated_result



testWords = ['a', "this is an str", "The quick brown fox jumps over the lazy dog"]

print("--------For testing we are using pythons module hashlib--------")
for word in testWords:
    result = MD4(word)
    hashObject = hashlib.new('md4', word.encode('utf-8'))
    digest = hashObject.hexdigest()
    print("For Test word: {0}".format(word))
    print("Result is: {0}".format(result))
    if(result == digest):
        print("TEST PASSED")
    else:
        print("TEST FAILED")


word = input("Type a word: ")
if word == "":
    print("Empty String exiting...")
    exit()

print(MD4(word))

