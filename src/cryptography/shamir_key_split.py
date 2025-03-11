import secrets
from secretsharing import PlaintextToHexSecretSharer

def split_aes_key(aes_key, total_parts=5, threshold=3):
    """
    Splits the AES key into multiple shares using Shamir's Secret Sharing.
    
    :param aes_key:     The AES key in bytes.
    :param total_parts: Number of shares to generate (N).
    :param threshold:   Minimum shares needed to reconstruct the key (K).
    :return:            List of shares (strings).
    """
    # Convert AES key bytes to a hex string
    hex_key = aes_key.hex()

    # Create shares
    shares = PlaintextToHexSecretSharer.split_secret(
        hex_key, threshold, total_parts
    )
    return shares

def recover_aes_key(shares):
    """
    Recovers the AES key from the given shares.
    
    :param shares: List of share strings.
    :return:       Original AES key in bytes.
    """
    # Recover the hex string of the AES key
    recovered_hex_key = PlaintextToHexSecretSharer.recover_secret(shares)
    # Convert back to bytes
    return bytes.fromhex(recovered_hex_key)

if __name__ == "__main__":
    # Example usage:
    # Suppose we have an AES key from step 1
    example_aes_key = secrets.token_bytes(32)  # 256-bit key
    print("[*] Original AES key:", example_aes_key.hex())

    # Split the key into 5 parts, requiring 3 parts to reconstruct
    shares = split_aes_key(example_aes_key, total_parts=5, threshold=3)
    print("\n[+] Generated shares:")
    for i, share in enumerate(shares, 1):
        print(f" Share #{i}: {share}")

    # Suppose we only have 3 of those shares
    subset_of_shares = shares[:3]  # pick any 3
    recovered_key = recover_aes_key(subset_of_shares)
    print(f"\n[*] Recovered AES key (from 3 shares): {recovered_key.hex()}")

    # Verify correctness
    print("\n[*] Keys match:", recovered_key == example_aes_key)
