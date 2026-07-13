"""
=============================================================
Quantum Random Number Generator (QRNG)
-------------------------------------------------------------
Provides a unified random number interface for the
PQC-VANET system.

Current Backend:
    ✔ Local Cryptographically Secure RNG (os.urandom)

Future Backends:
    ✔ ANU Quantum RNG
    ✔ IBM Quantum RNG

Author : Meeth Amin
=============================================================
"""

import os
import secrets
import hashlib
import time

# ==========================================================
# Local Secure Random Generator
# ==========================================================

def generate_random_bytes(length: int = 32) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Parameters
    ----------
    length : int
        Number of random bytes.

    Returns
    -------
    bytes
        Random bytes.
    """

    return os.urandom(length)


# ==========================================================
# Generate Random Integer
# ==========================================================

def generate_random_int(bits: int = 256) -> int:
    """
    Generate a secure random integer.

    Parameters
    ----------
    bits : int

    Returns
    -------
    int
    """

    return secrets.randbits(bits)


# ==========================================================
# Generate Random Hex String
# ==========================================================

def generate_random_hex(length: int = 32) -> str:
    """
    Generate random hexadecimal string.
    """

    return generate_random_bytes(length).hex()


# ==========================================================
# Generate Nonce
# ==========================================================

def generate_nonce(length: int = 32) -> bytes:
    """
    Generate nonce.
    """

    return generate_random_bytes(length)


# ==========================================================
# Generate Vehicle Secret Value
# ==========================================================

def generate_secret_value() -> bytes:
    """
    Generate vehicle secret value.
    """

    return generate_random_bytes(32)


# ==========================================================
# Generate Pseudonym Seed
# ==========================================================

def generate_pseudonym_seed() -> bytes:
    """
    Generate seed for pseudonym generation.
    """

    return generate_random_bytes(32)


# ==========================================================
# Generate Session Identifier
# ==========================================================

def generate_session_id() -> str:
    """
    Unique Session Identifier.
    """

    timestamp = str(time.time()).encode()

    rnd = generate_random_bytes(32)

    return hashlib.sha3_256(
        timestamp + rnd
    ).hexdigest()


# ==========================================================
# Health Check
# ==========================================================

def health_check():

    print("=" * 60)
    print("QRNG HEALTH CHECK")
    print("=" * 60)

    rnd1 = generate_random_hex()

    rnd2 = generate_random_hex()

    print("Random 1 :", rnd1)

    print("Random 2 :", rnd2)

    print()

    print("Equal :", rnd1 == rnd2)

    print("=" * 60)


# ==========================================================
# Demo
# ==========================================================

if __name__ == "__main__":

    health_check()