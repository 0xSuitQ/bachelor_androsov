from cryptography.aes_encryption import generate_aes_key, encrypt_file, decrypt_file
from cryptography.shamir_key_split import split_aes_key, recover_aes_key

aes_key = generate_aes_key()
encrypt_file(aes_key, 'example_input.txt', 'encrypted_output.bin')

shares = split_aes_key(aes_key, total_parts=5, threshold=3)

recovered_key = recover_aes_key(shares[:3])

decrypt_file(recovered_key, 'encrypted_output.bin', 'decrypted_output.txt')
