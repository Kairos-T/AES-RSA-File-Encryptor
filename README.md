# AES-RSA-File-Encryptor


This Python script allows you to encrypt and decrypt files using AES and RSA encryption.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/Kairos-T/AES-RSA-File-Encryptor
   ```

2. Navigate to the project directory
    ```bash
    cd AES-RSA-File-Encryptor
    ```

3. Install the required packages using pip:
    ```bash
    pip install -r requirements.txt
    ```

4. Run the script with the following commands:
    ```bash
    python app.py <encrypt/decrypt> <input_file> <output_file> <private_key_file>
    ```
    - `encrypt/decrypt`: Specify whether you want to encrypt or decrypt the file
    - `input_file`: Path to the input file you want to encrypt or decrypt.
    - `output_file`: Path where the encrypted or decrypted file will be saved.
    - `private_key_file`:  Path to the RSA private key file for decryption (only required for decryption).
