#Imports

import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

AES_blocksize = 16
AES_padding = b'\x00'

#RSA Key Pair
key = RSA.generate(2048) 
private_key = key.export_key()
public_key = key.publickey().export_key()

# RSA Key write to file
with open('private_key.pem', 'wb') as f:
    f.write(private_key)
with open('public_key.pem', 'wb') as f:
    f.write(public_key)

def generate_aes_key():
    """Generate a random AES key."""
    return get_random_bytes(AES_blocksize)

def encrypt_file(filename, aes_key, rsa_public_key):
    """Encrypt a file using AES and RSA."""
    #Read file contents
    with open(filename, 'rb') as file:
        plaintext = file.read()

    #Pad the plaintext to be a multiple of AES block size
    plaintext += AES_padding * (AES_blocksize - len(plaintext) % AES_blocksize)

    #Generate AES cipher using the AES key
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)

    #Encrypt the plaintext using AES
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    #Encrypt the AES key using RSA public key
    rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    #Writing encrypted AES key and ciphertext to output fo;e
    with open('encrypted_' + filename, 'wb') as output_file:
        output_file.write(encrypted_aes_key)
        output_file.write(aes_cipher.nonce)
        output_file.write(tag)
        output_file.write(ciphertext) 

def decrypt_file(filename, aes_key, rsa_private_key):
    """Decrypt a file using AES and RSA."""
    
