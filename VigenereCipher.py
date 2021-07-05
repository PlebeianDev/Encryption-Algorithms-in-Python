import math

def set_cipher_list():
    c = 'a'
    cipher_list = []
    while(c <= 'z'):
        c_list = []
        x = c
        for i in range(26):
            if x > 'z':
                x = 'a'
            c_list.append(chr(ord(x)-32)) #turn char to its capital form -> int(a) - 32  => int(A) and then cast it to char
            x = chr(ord(x) + 1)
        cipher_list.append(c_list)
        c = chr(ord(c) + 1)
    return cipher_list

def key_str(word, key):
    num = math.ceil(len(word)/len(key))
    return key * num

def encrypt(cipher_list, key, word):
    encrypted_word = ""
    for i in range(len(word)):
        encrypted_word += cipher_list[ord(key[i])-97][ord(word[i])-97]
    return encrypted_word
    




cipher_list = set_cipher_list()


word = "wearediscoveredsaveyourself"
key = "deceptive"



print(cipher_list[ ord(key[0])-97 ] )
word = word.lower().replace(" ", "")
print(word)



key = key_str(word, key)

encrypted_word = encrypt(cipher_list, key, word)
print(encrypted_word)






