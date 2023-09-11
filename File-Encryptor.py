import os
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY_LENGTH = 32  # 256 bits
RSA_KEY_LENGTH = 2048

def generate_aes_key():
    return get_random_bytes(AES_KEY_LENGTH)

def encrypt_file(input_filename, output_filename, aes_key, rsa_public_key):
    try:
        with open(input_filename, 'rb') as file:
            plaintext = file.read()

        # Pad the plaintext to be a multiple of AES block size
        padded_plaintext = pad(plaintext, AES.block_size)

        # Generate AES cipher using the AES key
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)

        # Encrypt the plaintext using AES
        ciphertext, tag = aes_cipher.encrypt_and_digest(padded_plaintext)

        # Encrypt the AES key using RSA public key
        rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        # Write encrypted AES key, nonce, tag, and ciphertext to the output file
        with open(output_filename, 'wb') as output_file:
            output_file.write(encrypted_aes_key)
            output_file.write(aes_cipher.nonce)
            output_file.write(tag)
            output_file.write(ciphertext)

        print(f"Encryption complete. Encrypted file saved as '{output_filename}'")

    except Exception as e:
        print(f"Error: {str(e)}")

def decrypt_file(input_filename, output_filename, rsa_private_key):
    try:
        # Read encrypted file contents
        with open(input_filename, 'rb') as file:
            encrypted_data = file.read()

        # Extract AES cipher nonce, tag, and ciphertext from encrypted data
        encrypted_aes_key_size = rsa_private_key.size_in_bytes()
        nonce = encrypted_data[:AES.block_size]
        tag = encrypted_data[AES.block_size:AES.block_size + 16]
        ciphertext = encrypted_data[AES.block_size + 16:encrypted_aes_key_size]

        # Decrypt the AES key using RSA private key
        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        aes_key = rsa_cipher.decrypt(encrypted_data[:RSA_KEY_LENGTH // 8])

        # Create AES cipher using decrypted AES key and extracted nonce
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

        # Decrypt the ciphertext using AES
        decrypted_data = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)

        # Write the decrypted plaintext to the output file
        with open(output_filename, 'wb') as output_file:
            output_file.write(decrypted_data)

        print(f"Decryption complete. Decrypted file saved as '{output_filename}'")

    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    if len(sys.argv) != 5:
        print("Usage: python file_encrypt_decrypt.py <encrypt/decrypt> <input_file> <output_file> <private_key_file>")
        sys.exit(1)

    operation = sys.argv[1]
    input_filename = sys.argv[2]
    output_filename = sys.argv[3]
    private_key_filename = sys.argv[4]

    if operation == "encrypt":
        aes_key = generate_aes_key()
        rsa_private_key = RSA.import_key(open(private_key_filename).read())
        encrypt_file(input_filename, output_filename, aes_key, rsa_private_key)
    elif operation == "decrypt":
        rsa_private_key = RSA.import_key(open(private_key_filename).read())
        decrypt_file(input_filename, output_filename, rsa_private_key)
    else:
        print("Invalid operation. Use 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
