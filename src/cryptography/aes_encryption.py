import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_aes_key(key_size=32):
    """
    Generates a random AES key of `key_size` bytes (default 32 = 256 bits).
    """
    return os.urandom(key_size)

def encrypt_file(aes_key, in_filename, out_filename):
    """
    Encrypts the file located at in_filename using AES-256 (CBC mode),
    and writes the encrypted data to out_filename.
    """
    # Generate a random 16-byte IV (block size for AES = 16 bytes)
    iv = os.urandom(16)

    # Create an AES cipher in CBC mode
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Read file data
    with open(in_filename, 'rb') as f_in:
        plaintext = f_in.read()

    # Pad the plaintext to be a multiple of the block size
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write the IV + ciphertext to the output file
    with open(out_filename, 'wb') as f_out:
        f_out.write(iv + ciphertext)

    print(f"[+] File '{in_filename}' encrypted successfully.")
    print(f"    IV and ciphertext written to '{out_filename}'.")

def decrypt_file(aes_key, in_filename, out_filename):
    """
    Decrypts the file located at in_filename using AES-256 (CBC mode) with
    the provided aes_key, and writes the decrypted data to out_filename.
    """
    # Read IV + ciphertext from the input file
    with open(in_filename, 'rb') as f_in:
        file_data = f_in.read()
    iv = file_data[:16]
    ciphertext = file_data[16:]

    # Create the AES cipher for decryption
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt and unpad
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)

    # Write the decrypted data
    with open(out_filename, 'wb') as f_out:
        f_out.write(decrypted)

    print(f"[+] File '{in_filename}' decrypted successfully.")
    print(f"    Decrypted data written to '{out_filename}'.")

if __name__ == "__main__":
    # Example usage:
    aes_key = generate_aes_key()  # 256-bit key
    print("[*] Generated AES-256 key:", aes_key.hex())

    # Encrypt a file
    encrypt_file(aes_key, 'example_input.txt', 'encrypted_output.bin')

    # Decrypt the file
    decrypt_file(aes_key, 'encrypted_output.bin', 'decrypted_output.txt')
