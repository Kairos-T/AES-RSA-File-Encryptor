# AES-RSA-File-Encryptor
Installation of pycryptodome library is required.

File-Encryptor.py contains the original code 
Break-down-of-code.py contains the original code with explanations along the way on each block of code

About the file encryptor:
This (basic) AES and RSA file encryptor provides functions to encrypt and decrypt files using the AES and RSA cryptography algorithms. 

It uses a way to encrypt files using a combination of symmetric and assymmetric (AES and RSA respectively) encryption, where AES is used to encrypt the file contents, whereas RSA is used for encrypting the AES key. Thus, this provides a higher level of security for file encryption. 

A summary of what this encryptor does:
1. Generates RSA key pair
    - Generates 2048-bit RSA key pair consisting of a private and public key
2. Writes RSA key to file
    - Writes generated keys to separate files in PEM format (File I/O)
3. AES generation: Generates a random 16-byte AES key (from Crypto.random module -> get_random_bytes())
4. File encryption: Reads content of file, pads plaintext to be a multiple of the AES block size. Generates AES cipher using AES key, and encrypts the plaintext using AES. Then it encrypts the AES key using the RSA public key, and writes the AES encrypted key, nonce, tag and ciphertext to an output file.
5. File decryption: Reads content of the encrypted file, extracts the encrypted data and decrypts the AES key using the RSA private key and generates the AES cipher using AES key and nonce. Then decrypts the ciphertext using AES and writes the decrypted plaintext to an output file. 