from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    plaintex = b'This is the message to encrypt but the attacker knows there is a specific sequence of numbers 12345'
    #attacker knows that there is 1 in a specific position
    index = plaintex.index(b'2')
    print(index)

    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key= key, nonce= nonce)
    ciphertext = cipher.encrypt(plaintex)

    #ciphertext, index, b'1'
    new_value = b'8'
    new_int = ord(new_value) #ASCII code

    mask = ord(b'2') ^ new_int
    edt_ciphertext = bytearray(ciphertext)
    edt_ciphertext[index] = ciphertext[index] ^ mask

    ######################
    cipher_dec = ChaCha20.new(key=key, nonce=nonce)
    decrypted_text = cipher_dec.decrypt(edt_ciphertext)
    print(decrypted_text)