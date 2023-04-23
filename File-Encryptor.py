#Imports

import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

#RSA Key Pair
key = RSA.generate(2048) 
private_key = key.export_key()
public_key = key.publickey().export_key()