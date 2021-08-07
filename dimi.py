from dimicrypt import encrypt_triple_des_ecb, decrypt_triple_des_ecb

if __name__ == '__main__':
    enc = encrypt_triple_des_ecb(
        message='When the darkness prevails; '
        'when the moon stops shining; '
        'when you start to question your logic; '
        'when you start to question your profession; '
        'Remember; '
        'It was just a missing semicolon on line 42.',
        key='answer'
    )
    print(f'enc\t\t: {enc:0X}')
    dec = decrypt_triple_des_ecb(
        encrypted_message=enc,
        key='answer'
    )
    print(f'dec\t\t: {dec}')
