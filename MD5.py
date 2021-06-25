from bitarray import bitarray
import math
import struct
import hashlib

def left_rotation(x, n):
    x = int(x)
    return (x << n) | (x >> (32 -n))

    
def modular_add(a,b):
    # The concept of modular addition : https://en.wikipedia.org/wiki/Modular_arithmetic
    # Here we use modular addition with 2^32
    result = (a + b) % math.pow(2, 32)
    print("ADDING:{0} + {1} = {2}".format(a,b,result))
    return result

word = "str"

s = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, 
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 
    ]

K = [] # Sin_tanle
for i in range(64):
    #calculate sin_table
    K.append(math.floor(math.pow(2,32) * abs(math.sin(i+1) )) )

a0 = 0x67452301
b0 = 0xefcdab89 
c0 = 0x98badcfe  
d0 = 0x10325476 


array = bitarray(endian="big")
array.frombytes(word.encode("Utf-8"))
print("ORIGINAL WORD:{0}".format(array))
#print(len(array))

array.append(1)
while len(array) % 512 != 448:
    array.append(0)
print("PADDED WORD {0}".format(array))
print(len(array))

length = int((len(word) * 8) % math.pow(2, 64))

#apppend original length as 64 bit number
#length = int((len(word) * 8) % math.pow(2, 64))
#print(length)

#array_of_bits = bitarray(endian="big")
#array_of_bits.frombytes()
length = len(word) * 8
bytes_to_num = format(length, "b")
print(bytes_to_num)
array_of_bits = bitarray(endian="big")
for i in range(64-len(word)):
    array_of_bits.append(0)
for b in bytes_to_num:
    array_of_bits.append(int(b))


