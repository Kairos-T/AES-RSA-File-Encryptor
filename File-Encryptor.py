#Imports

import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

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
    return get_random_bytes(16)

def encrypt_file(filename, aes_key, rsa_public_key):
    """Encrypt a file using AES and RSA."""
    ...

def decrypt_file(filename, aes_key, rsa_private_key):
    """Decrypt a file using AES and RSA."""
    ...
