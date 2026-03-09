"""
Feistel Cipher - Core Implementation
=====================================
Educational implementation of a Feistel Network block cipher.

Key concepts demonstrated:
  - Splitting a block into two halves (L and R)
  - Applying a round function F to mix the halves
  - Running multiple rounds for better security
  - Decryption using the same structure (just reverse key order)

Block size : 8 bytes (64 bits)
Key size   : 4 bytes (32 bits)  <-- for simplicity only
Rounds     : 4 (configurable)

"""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BLOCK_SIZE = 8   # bytes per block (64 bits total)
HALF_SIZE  = 4   # bytes per half  (32 bits each)
ROUNDS     = 4   # number of Feistel rounds

MASK32 = 0xFFFFFFFF  # used to keep values within 32 bits


# ---------------------------------------------------------------------------
# Key scheduling
# ---------------------------------------------------------------------------

def generate_round_keys(master_key: int) -> list[int]:
    """
    Derive one round key per round from the master key.

    This is intentionally simple: multiply the master key by (round + 1).
    Real ciphers (DES, AES) use more complex key schedules.
    """
    round_keys = []
    for i in range(ROUNDS):
        # Multiply and mask to stay within 32 bits
        round_key = (master_key * (i + 1)) & MASK32
        round_keys.append(round_key)
    return round_keys


# ---------------------------------------------------------------------------
# Round function F
# ---------------------------------------------------------------------------

def F(right: int, round_key: int) -> int:
    """
    The round function mixes the right half with the round key.

    Using only XOR here keeps the logic transparent for students.
    Real ciphers use substitution boxes (S-boxes) and permutations.

    Try experimenting with:
      return (right + round_key) & MASK32          # addition
      return bin(right ^ round_key).count('1')     # bit counting
    """
    return (right ^ round_key) & MASK32


# ---------------------------------------------------------------------------
# Single-block encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_block(block: bytes, round_keys: list[int]) -> bytes:
    """
    Encrypt a single 8-byte block using the Feistel structure.

    Each round:
      new_L = R
      new_R = L XOR F(R, round_key)

    The left and right halves swap every round, mixing the data.
    """
    assert len(block) == BLOCK_SIZE, f"Block must be {BLOCK_SIZE} bytes"

    # Split the block into two 32-bit halves (big-endian)
    L = int.from_bytes(block[:HALF_SIZE], byteorder='big')
    R = int.from_bytes(block[HALF_SIZE:], byteorder='big')

    for i in range(ROUNDS):
        new_L = R
        new_R = (L ^ F(R, round_keys[i])) & MASK32
        L, R = new_L, new_R

    # Reassemble the two halves into 8 bytes
    return (
        L.to_bytes(HALF_SIZE, byteorder='big') +
        R.to_bytes(HALF_SIZE, byteorder='big')
    )


def decrypt_block(block: bytes, round_keys: list[int]) -> bytes:
    """
    Decrypt a single 8-byte block.

    Feistel networks are symmetric: decryption uses the SAME structure
    as encryption — you only need to reverse the order of round keys.
    No inverse function for F is required!
    """
    assert len(block) == BLOCK_SIZE, f"Block must be {BLOCK_SIZE} bytes"

    L = int.from_bytes(block[:HALF_SIZE], byteorder='big')
    R = int.from_bytes(block[HALF_SIZE:], byteorder='big')

    # Reverse the round keys for decryption
    for i in reversed(range(ROUNDS)):
        new_R = L
        new_L = (R ^ F(L, round_keys[i])) & MASK32
        L, R = new_L, new_R

    return (
        L.to_bytes(HALF_SIZE, byteorder='big') +
        R.to_bytes(HALF_SIZE, byteorder='big')
    )


# ---------------------------------------------------------------------------
# Multi-block (ECB mode): handle messages of any length
# ---------------------------------------------------------------------------

def pad(data: bytes) -> bytes:
    """
    Pad the data with spaces so its length is a multiple of BLOCK_SIZE.
    Last block may be shorter — we fill it up with 0x20 (ASCII space).
    """
    remainder = len(data) % BLOCK_SIZE
    if remainder != 0:
        data += b' ' * (BLOCK_SIZE - remainder)
    return data


def encrypt(plaintext: str, master_key: int) -> bytes:
    """
    Encrypt a plaintext string of any length.

    Steps:
      1. Encode the string to bytes (UTF-8)
      2. Pad to a multiple of BLOCK_SIZE
      3. Split into 8-byte blocks
      4. Encrypt each block independently (ECB mode)
      5. Return all ciphertext blocks concatenated
    """
    data = plaintext.encode('utf-8')
    data = pad(data)
    round_keys = generate_round_keys(master_key)

    ciphertext = b''
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        ciphertext += encrypt_block(block, round_keys)

    return ciphertext


def decrypt(ciphertext: bytes, master_key: int) -> str:
    """
    Decrypt ciphertext bytes back to a plaintext string.

    Mirrors encrypt(): process each block and strip padding at the end.
    """
    round_keys = generate_round_keys(master_key)

    plaintext_bytes = b''
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext_bytes += decrypt_block(block, round_keys)

    # Remove the space padding added during encryption
    return plaintext_bytes.decode('utf-8').rstrip(' ')