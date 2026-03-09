"""
Feistel Cipher - Demo Application
===================================
Run this file to see the cipher in action.

Usage:
  python feistel_app.py                        # default plaintext
  python feistel_app.py "Hello World"          # custom plaintext
  python feistel_app.py Hello World longer     # multiple words joined

Demos included:
  1. Encrypt / Decrypt a message
  2. Avalanche Effect  — 1 character change -> 50% of bits flip
  3. ECB Weakness      — identical blocks produce identical ciphertext
"""

import sys
from feistel import decrypt, encrypt_block, generate_round_keys, BLOCK_SIZE

# ---------------------------------------------------------------------------
# Master key (32-bit integer — change this to see different ciphertexts)
# ---------------------------------------------------------------------------
MASTER_KEY = 0x12345678


# ---------------------------------------------------------------------------
# Helper: show a block as a hex string like 0x48656C6C6F2C2077
# ---------------------------------------------------------------------------

def to_hex(data: bytes) -> str:
    return "0x" + data.hex().upper()


# ---------------------------------------------------------------------------
# Helper: count how many bits differ between two byte strings
# ---------------------------------------------------------------------------

def count_differing_bits(a: bytes, b: bytes) -> int:
    diff = 0
    for byte_a, byte_b in zip(a, b):
        xor = byte_a ^ byte_b          # bits that differ become 1
        diff += bin(xor).count('1')    # count those 1s
    return diff


# ---------------------------------------------------------------------------
# Demo 1 — Encrypt and decrypt a full message
# ---------------------------------------------------------------------------

def demo_encrypt_decrypt(plaintext: str):
    data = plaintext.encode('utf-8')
    # Pad manually to show block count
    remainder = len(data) % BLOCK_SIZE
    padded_len = len(data) + (BLOCK_SIZE - remainder if remainder else 0)
    block_count = padded_len // BLOCK_SIZE

    print("=== INPUT ===")
    print(f'Plaintext:   "{plaintext}"')
    print(f"Length:      {len(plaintext)} characters")
    print(f"Blocks:      {block_count} blocks ({BLOCK_SIZE} bytes each)")

    # --- Encryption ---
    print("\n=== ENCRYPTION ===")
    round_keys = generate_round_keys(MASTER_KEY)

    ciphertext_blocks = []
    padded = data.ljust(padded_len, b' ')  # pad with spaces

    for i in range(block_count):
        plain_block  = padded[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        cipher_block = encrypt_block(plain_block, round_keys)
        ciphertext_blocks.append(cipher_block)
        print(f"  Block {i}: {to_hex(plain_block)} -> {to_hex(cipher_block)}")

    # --- Decryption ---
    print("\n=== DECRYPTION ===")
    from feistel import decrypt_block
    for i, cipher_block in enumerate(ciphertext_blocks):
        plain_block = decrypt_block(cipher_block, round_keys)
        print(f"  Block {i}: {to_hex(cipher_block)} -> {to_hex(plain_block)}")

    # --- Results ---
    ciphertext = b''.join(ciphertext_blocks)
    decrypted  = decrypt(ciphertext, MASTER_KEY)

    print("\n=== RESULTS ===")
    print(f'Original:    "{plaintext}"')
    print(f'Decrypted:   "{decrypted}"')
    print(f"Match:       {plaintext == decrypted}")


# ---------------------------------------------------------------------------
# Demo 2 — Avalanche Effect
# ---------------------------------------------------------------------------

def demo_avalanche():
    """
    Change a single character and show how much the ciphertext changes.
    A good cipher should flip ~50% of the output bits.
    """
    original = "Crypto!!"
    modified = "Cryptp!!"   # only the 7th character differs ('o' -> 'p')

    round_keys = generate_round_keys(MASTER_KEY)

    orig_bytes  = original.encode('utf-8')
    mod_bytes   = modified.encode('utf-8')

    orig_cipher = encrypt_block(orig_bytes, round_keys)
    mod_cipher  = encrypt_block(mod_bytes,  round_keys)

    diff_bits   = count_differing_bits(orig_cipher, mod_cipher)
    total_bits  = BLOCK_SIZE * 8  # 64

    print("\n=== AVALANCHE EFFECT DEMO ===")
    print(f'Original input:  "{original}" -> {to_hex(orig_cipher)}')
    print(f'Modified input:  "{modified}" -> {to_hex(mod_cipher)}')
    print(f"Difference:      {diff_bits} out of {total_bits} bits changed "
          f"({100 * diff_bits / total_bits:.1f}%)")
    print("Note: Good ciphers should change ~50% of bits for any small input change.")


# ---------------------------------------------------------------------------
# Demo 3 — ECB Mode Weakness
# ---------------------------------------------------------------------------

def demo_ecb_weakness():
    """
    ECB mode encrypts each block independently, so identical plaintext
    blocks always produce identical ciphertext blocks.

    An attacker can spot patterns in the ciphertext without decrypting it!
    """
    plaintext = "AAAAAAAAAAAAAAAAABBBBBBBB"
    #            |---block 0---||---block 1---||---block 2---|
    #            (8 × 'A')      (8 × 'A')      (8 × 'B')

    from feistel import pad
    data       = plaintext.encode('utf-8')
    padded     = pad(data)
    round_keys = generate_round_keys(MASTER_KEY)
    block_count = len(padded) // BLOCK_SIZE

    print("\n=== ECB MODE WEAKNESS DEMO ===")
    print(f'Plaintext with repeated blocks: "{plaintext}"')

    cipher_blocks = []
    for i in range(block_count):
        plain_block  = padded[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        cipher_block = encrypt_block(plain_block, round_keys)
        cipher_blocks.append(cipher_block)
        print(f'  Block {i}: "{plain_block.decode()}" -> {to_hex(plain_block)}')

    print("\nCiphertext blocks:")
    for i, cb in enumerate(cipher_blocks):
        print(f"  Cipher {i}: {to_hex(cb)}")

    print()
    if cipher_blocks[0] == cipher_blocks[1]:
        print("Notice: Blocks 0 and 1 are IDENTICAL! This is ECB's weakness.")
        print("An attacker can see patterns in the plaintext by observing ciphertext.")
    else:
        print("Blocks differ — review block boundaries if this is unexpected.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Accept custom plaintext from command line (like the Java version)
    if len(sys.argv) > 1:
        plaintext = " ".join(sys.argv[1:])
    else:
        plaintext = "Hello, what are you doing"

    demo_encrypt_decrypt(plaintext)
    demo_avalanche()
    demo_ecb_weakness()