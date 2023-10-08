import sys
import logging
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY_LENGTH = 32  # 256 bits
RSA_KEY_LENGTH = 2048
BLOCK_SIZE = AES.block_size
ENCRYPT_MODE = "encrypt"
DECRYPT_MODE = "decrypt"


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )


def generate_aes_key():
    return get_random_bytes(AES_KEY_LENGTH)


def encrypt_file(input_filename, output_filename, aes_key, rsa_public_key):
    try:
        with open(input_filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
            plaintext = input_file.read()

            # Pad the plaintext to be a multiple of AES block size
            padded_plaintext = pad(plaintext, BLOCK_SIZE)

            # Generate AES cipher using the AES key
            aes_cipher = AES.new(aes_key, AES.MODE_EAX)

            # Encrypt the plaintext using AES
            ciphertext, _ = aes_cipher.encrypt_and_digest(padded_plaintext)

            # Encrypt the AES key using RSA public key
            rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)

            # Write encrypted AES key, nonce, and ciphertext to the output file
            output_file.write(encrypted_aes_key)
            output_file.write(aes_cipher.nonce)
            output_file.write(ciphertext)

        logging.info(f"Encryption complete. Encrypted file saved as '{output_filename}'")

    except FileNotFoundError:
        logging.error(f"Error: File not found - {input_filename}")
    except Exception as e:
        logging.error(f"Error: {str(e)}")


def decrypt_file(input_filename, output_filename, rsa_private_key):
    try:
        with open(input_filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
            encrypted_data = input_file.read()

            # Extract AES cipher nonce and ciphertext from encrypted data
            encrypted_aes_key_size = rsa_private_key.size_in_bytes()
            nonce = encrypted_data[AES_KEY_LENGTH:AES_KEY_LENGTH + BLOCK_SIZE]
            ciphertext = encrypted_data[AES_KEY_LENGTH + BLOCK_SIZE:]

            # Decrypt the AES key using RSA private key
            rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
            aes_key = rsa_cipher.decrypt(encrypted_data[:encrypted_aes_key_size])

            # Create AES cipher using decrypted AES key and extracted nonce
            aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

            # Decrypt the ciphertext using AES
            decrypted_data = unpad(aes_cipher.decrypt(ciphertext), BLOCK_SIZE)

            # Write the decrypted plaintext to the output file
            output_file.write(decrypted_data)

        logging.info(f"Decryption complete. Decrypted file saved as '{output_filename}'")

    except FileNotFoundError:
        logging.error(f"Error: File not found - {input_filename}")
    except Exception as e:
        logging.error(f"Error: {str(e)}")


def main():
    if len(sys.argv) != 5:
        print("Usage: python file_encrypt_decrypt.py <encrypt/decrypt> <input_file> <output_file> <private_key_file>")
        sys.exit(1)

    configure_logging()
    operation = sys.argv[1]
    input_filename = sys.argv[2]
    output_filename = sys.argv[3]
    private_key_filename = sys.argv[4]

    if operation == ENCRYPT_MODE:
        aes_key = generate_aes_key()
        rsa_private_key = RSA.import_key(open(private_key_filename).read())
        encrypt_file(input_filename, output_filename, aes_key, rsa_private_key)
    elif operation == DECRYPT_MODE:
        rsa_private_key = RSA.import_key(open(private_key_filename).read())
        decrypt_file(input_filename, output_filename, rsa_private_key)
    else:
        print("Invalid operation. Use 'encrypt' or 'decrypt'.")


if __name__ == "__main__":
    main()
