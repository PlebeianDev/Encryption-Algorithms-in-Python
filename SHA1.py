import struct

h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0

def shift(n, x):
    return ((n << x) | (n >> (32-x))) & 0xFFFFFFFF

word = input("Type word:")


#turn word to bytes
array = bytes(word, "utf-8")


#first add 1 ,then 0 and then the sizeof word
padding =  b"\x80" + b"\x00" * (63 - (len(word) + 8) % 64)
padded_word = array + padding + struct.pack(">Q", 8 * len(word))

blocks = []
blocks =[ padded_word[i : i + 64] for i in range(0, len(padded_word), 64) ]

for block in blocks:
    #extend word
    word_extended = list(struct.unpack(">16L",block)) + [0]* 64
    for i in range(16, 80):
        word_extended[i] = shift((word_extended[i - 3] ^ word_extended[i - 8] ^ word_extended[i - 14] ^ word_extended[i - 16]), 1)
    #init values
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4 
    F = 0
    k = 0
    for i in range(0,80):
        if 0 <= i <= 19:
            F = ( b & c ) | ((~b) & d)
            k = 0x5A827999 
        elif 20 <= i <= 39:
            F = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            F = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            F = b ^ c ^ d
            k = 0xCA62C1D6
        a, b, c, d, e = (
                    shift(a, 5) + F + e + k + word_extended[i] & 0xFFFFFFFF,
                    a,
                    shift(b, 30),
                    c,
                    d,
                )
    h = (h0 + a & 0xFFFFFFFF,
    h1 + b & 0xFFFFFFFF,
    h2 + c & 0xFFFFFFFF,
    h3 + d & 0xFFFFFFFF,
    h4 + e & 0xFFFFFFFF,
    )
    result = "%08x%08x%08x%08x%08x" % tuple(h)
    print(result)


    
