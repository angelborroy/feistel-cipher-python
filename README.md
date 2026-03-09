# feistel-cipher-python

Sample implementation of a Feistel Cipher for students learning Python.

Python equivalent of [feistel-cipher-sample](https://github.com/angelborroy/feistel-cipher-sample): same logic, same demos, zero dependencies.

## Overview

This educational implementation demonstrates:

- **Feistel network structure**: How left/right halves are swapped and mixed using XOR
- **Block cipher operation**: Processing fixed 64-bit (8-byte) blocks
- **ECB-like mode**: Handling messages longer than one block by encrypting each independently
- **Avalanche effect**: How a 1-character change flips ~50% of the output bits
- **ECB weakness**: Why identical plaintext blocks produce identical ciphertext

> **Security Warning**: Educational purposes only. Do NOT use in production.

## Requirements

Python 3.10 or higher (uses `list[int]` type hints). No external libraries needed.

## Files

| File | Purpose |
|---|---|
| `feistel.py` | Core cipher logic — start here |
| `feistel_app.py` | Demo application (encrypt, avalanche, ECB weakness) |

## Running

```bash
# Default plaintext
python feistel_app.py

# Custom plaintext
python feistel_app.py "Alice in Wonderland"

# Multiple words joined automatically
python feistel_app.py Hello world this is a test
```

### Example Output

```
=== INPUT ===
Plaintext:   "Hello, what are you doing"
Length:      25 characters
Blocks:      4 blocks (8 bytes each)

=== ENCRYPTION ===
  Block 0: 0x48656C6C6F2C2077 -> 0x...
  Block 1: 0x6861742061726520 -> 0x...
  ...

=== RESULTS ===
Original:    "Hello, what are you doing"
Decrypted:   "Hello, what are you doing"
Match:       True

=== AVALANCHE EFFECT DEMO ===
Original input:  "Crypto!!" -> 0x...
Modified input:  "Cryptp!!" -> 0x...
Difference:      N out of 64 bits changed (X%)

=== ECB MODE WEAKNESS DEMO ===
...
Notice: Blocks 0 and 1 are IDENTICAL! This is ECB's weakness.
```

## Key Parameters (in `feistel.py`)

| Constant | Value | Meaning |
|---|---|---|
| `BLOCK_SIZE` | 8 | Bytes per block (64 bits) |
| `HALF_SIZE` | 4 | Bytes per half (32 bits) |
| `ROUNDS` | 4 | Number of Feistel rounds |

Change `MASTER_KEY` in `feistel_app.py` to use a different key.

## Experiments for Students

### Modify the Round Function

Open `feistel.py` and change `F()`:

```python
# Current (XOR only)
return (right ^ round_key) & MASK32

# Try: add rotation for better diffusion
import ctypes
return ctypes.c_uint32(right ^ round_key).value  # same but explicit

# Try: use addition
return (right + round_key) & MASK32

# Try: combine operations
return ((right ^ round_key) + round_key) & MASK32
```

### Change the Number of Rounds

```python
ROUNDS = 2   # fewer rounds → weaker cipher, patterns appear
ROUNDS = 8   # more rounds → stronger, harder to break
```

### Experiment with Keys

```python
MASTER_KEY = 0xDEADBEEF   # any 32-bit integer
MASTER_KEY = 0x00000001   # very weak key — observe the output
```

## Implementation Details

| Property | Value |
|---|---|
| Block size | 64 bits (8 bytes) |
| Key size | 32 bits (demo only) |
| Rounds | 4 (configurable) |
| Mode | ECB (independent block encryption) |
| Padding | Spaces (0x20) for incomplete blocks |
| Dependencies | None (pure Python) |

## Learning Objectives

1. **Feistel Structure** — Encryption and decryption use the same code (just reverse the key order)
2. **Block Cipher Basics** — Fixed-size block processing and padding
3. **Key Scheduling** — Deriving per-round keys from a master key
4. **ECB Mode** — Independent block encryption and its pattern vulnerability
5. **Avalanche Effect** — Small input changes cause large output changes
6. **XOR Properties** — Why XOR is used in cryptography