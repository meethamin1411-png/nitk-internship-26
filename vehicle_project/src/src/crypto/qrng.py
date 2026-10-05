"""
===========================================================
Quantum Random Number Generator (QRNG) Version 3
-----------------------------------------------------------
Backend

1. ANU Quantum Random Numbers
2. Quantum Seed Expansion
3. Local Fallback

Author : Meeth Amin
===========================================================
"""

import os
import time
import hashlib
import requests

# ==========================================================
# Configuration
# ==========================================================

API_URL = "https://api.quantumnumbers.anu.edu.au"

API_KEY = "mW8xPdvfkF8Zw4MiXg06a3s3Nb8wouFK9oDnbOmf"

TIMEOUT = 10

MASTER_SEED = None

_backend = "Local CSPRNG"
# ==========================================================
# Fetch Quantum Master Seed
# ==========================================================

def initialize_qrng():
    """
    Fetch a single 32-byte quantum seed from ANU.
    This is called once when the program starts.
    """

    global MASTER_SEED
    global _backend

    headers = {
        "x-api-key": API_KEY
    }

    params = {
        "length": 32,
        "type": "uint8"
    }

    try:

        response = requests.get(
            API_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )
        print("Status Code:", response.status_code)
        print("Response:", response.text)

        if response.status_code == 200:

            result = response.json()

            if result.get("success"):

                MASTER_SEED = bytes(result["data"])

                _backend = "ANU Quantum API"

                print("[QRNG] Quantum Seed Successfully Loaded")

                return

    except Exception as e:

        print("[QRNG] ANU unavailable:", e)

    # ------------------------------------------------------
    # Local Fallback
    # ------------------------------------------------------

    MASTER_SEED = os.urandom(32)

    _backend = "Local CSPRNG"

    print("[QRNG] Using Local Secure Seed")
    # ==========================================================
# Quantum Seed Expansion Engine
# ==========================================================

_counter = 0


def generate_random_bytes(length: int = 32) -> bytes:
    """
    Generate cryptographically secure random bytes
    derived from the Quantum Master Seed.

    ANU is contacted ONLY ONCE during initialization.
    """

    global MASTER_SEED
    global _counter

    # ---------------------------------------------
    # Initialize seed if not already initialized
    # ---------------------------------------------

    if MASTER_SEED is None:

        initialize_qrng()

    output = b""

    while len(output) < length:

        counter_bytes = _counter.to_bytes(8, "big")

        block = hashlib.sha3_512(
            MASTER_SEED + counter_bytes
        ).digest()

        output += block

        _counter += 1

    return output[:length]
    # ==========================================================
# Generate Random Integer
# ==========================================================

def generate_random_int(bits: int = 256) -> int:
    """
    Generate a quantum-seeded random integer.
    """

    byte_length = (bits + 7) // 8

    return int.from_bytes(
        generate_random_bytes(byte_length),
        byteorder="big"
    )


# ==========================================================
# Generate Random Hex String
# ==========================================================

def generate_random_hex(length: int = 32) -> str:
    """
    Generate a quantum-seeded hexadecimal string.
    """

    return generate_random_bytes(length).hex()


# ==========================================================
# Generate Nonce
# ==========================================================

def generate_nonce(length: int = 32) -> bytes:
    """
    Generate a quantum-seeded nonce.
    """

    return generate_random_bytes(length)


# ==========================================================
# Generate Vehicle Secret Value
# ==========================================================

def generate_secret_value() -> bytes:
    """
    Generate a quantum-seeded vehicle secret.
    """

    return generate_random_bytes(32)


# ==========================================================
# Generate Pseudonym Seed
# ==========================================================

def generate_pseudonym_seed() -> bytes:
    """
    Generate a quantum-seeded pseudonym seed.
    """

    return generate_random_bytes(32)


# ==========================================================
# Generate Session Identifier
# ==========================================================

def generate_session_id() -> str:
    """
    Generate a unique session identifier.
    """

    timestamp = str(time.time()).encode()

    rnd = generate_random_bytes(32)

    return hashlib.sha3_256(
        timestamp + rnd
    ).hexdigest()
    # ==========================================================
# QRNG Health Check
# ==========================================================

def health_check():
    """
    Test the QRNG backend.
    """

    print("=" * 65)
    print(" QUANTUM RANDOM NUMBER GENERATOR (QRNG) VERSION 3")
    print("=" * 65)

    start = time.perf_counter()

    rnd1 = generate_random_hex()

    end = time.perf_counter()

    rnd2 = generate_random_hex()

    print(f"Backend Used       : {_backend}")
    print(f"Master Seed Loaded : {MASTER_SEED is not None}")
    print(f"Random 1           : {rnd1}")
    print(f"Random 2           : {rnd2}")
    print(f"Equal              : {rnd1 == rnd2}")
    print(f"Generation Time    : {(end-start)*1000:.3f} ms")

    print("=" * 65)


# ==========================================================
# Demo
# ==========================================================

if __name__ == "__main__":

    initialize_qrng()

    health_check()