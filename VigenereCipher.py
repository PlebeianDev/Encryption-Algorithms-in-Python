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
    
def decrypt(cipher_list, key ,word):
    decrypted_word = ""

    for i in range(len(word)):
        x = ord(key[i])-97
        letter = word[i]
        #print(letter)
        for j in range(len(cipher_list[x])):
            if letter == cipher_list[x][j]:
                decrypted_word += chr(j+97)

    return decrypted_word
        



cipher_list = set_cipher_list()


word = "wearediscoveredsaveyourself"
key = "deceptive"




word = word.lower().replace(" ", "")


testWords = ['a', "this is an str", "The quick brown fox jumps over the lazy dog"]
testKey = "key"

key = key_str(word, key)

print("Testing starting....")
for word in testWords:
    print("For word: {0}".format(word))
    word = word.lower().replace(" ", "")
    print("Formatted word: {0}".format(word))
    key = key_str(word, testKey)
    encryptedWord = encrypt(cipher_list, key ,word)
    print("Encrypted word: {0}".format(encryptedWord))
    decryptedWord = decrypt(cipher_list, key ,encryptedWord)
    print("Decrypted word: {0}".format(decryptedWord))
    if decryptedWord == word:
        print("TEST PASSED")
    else:
        print("TEST FAILED")

 

encrypted_word = encrypt(cipher_list, key, word)
#print(encrypted_word)
decrypted_word = decrypt(cipher_list, key, encrypted_word)
print(decrypted_word)


word = input("Input word: ")
if word == "":
    print("Empty word exiting...")
    exit()
word = word.lower().replace(" ", "")
key = input("input key: ")
print(key)
if key == "":
    print("Empty key exiting...")
    exit()
key = key_str(word, key)
encryptedWord = encrypt(cipher_list, key, word)
print("Encrypted word: {0}".format(encryptedWord))
decryptedWord = decrypt(cipher_list, key, encryptedWord)
print(decryptedWord)








