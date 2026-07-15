"""
=========================================================
Hash Utilities
---------------------------------------------------------
Provides SHA3-256 based hashing utilities for
PQC-VANET.

Includes

• Generic SHA3-256 Hash
• Authentication Confidence Token (ACT)

ACT Formula

ACT = SHA3-256(
        PID ||
        SessionNonce ||
        RoadSegment ||
        VehicleState ||
        Timestamp
)

Author : Meeth Amin
=========================================================
"""

import hashlib
import hmac


# ==========================================================
# Generic SHA3-256 Hash
# ==========================================================

def sha3_hash(data):
    """
    Generate SHA3-256 hash.

    Parameters
    ----------
    data : str | bytes

    Returns
    -------
    str
        Hexadecimal SHA3-256 digest
    """

    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha3_256(data).hexdigest()


# ==========================================================
# Hash Raw Bytes
# ==========================================================

def hash_bytes(data: bytes):
    """
    Generate SHA3-256 hash from raw bytes.
    """

    return hashlib.sha3_256(data).hexdigest()


# ==========================================================
# Authentication Confidence Token (ACT)
# ==========================================================

def generate_act(
    pid,
    session_nonce,
    road_segment,
    vehicle_state,
    timestamp
):
    """
    Generate Authentication Confidence Token.

    ACT = SHA3-256(
            PID ||
            SessionNonce ||
            RoadSegment ||
            VehicleState ||
            Timestamp
    )
    """

    # ---------------------------------------------
    # PID
    # ---------------------------------------------

    if isinstance(pid, bytes):
        pid = pid.decode("utf-8")

    # ---------------------------------------------
    # Session Nonce
    # ---------------------------------------------

    if isinstance(session_nonce, bytes):
        nonce = session_nonce.hex()
    else:
        nonce = str(session_nonce)

    # ---------------------------------------------
    # Concatenate Fields
    # ---------------------------------------------

    payload = (

        str(pid)

        + nonce

        + str(road_segment)

        + str(vehicle_state)

        + str(timestamp)

    )

    # ---------------------------------------------
    # Generate ACT
    # ---------------------------------------------

    return hashlib.sha3_256(

        payload.encode("utf-8")

    ).hexdigest()


# ==========================================================
# Verify Authentication Confidence Token
# ==========================================================

def verify_act(
    received_act,
    pid,
    session_nonce,
    road_segment,
    vehicle_state,
    timestamp
):
    """
    Verify Authentication Confidence Token.
    """

    expected_act = generate_act(

        pid,

        session_nonce,

        road_segment,

        vehicle_state,

        timestamp

    )

    return hmac.compare_digest(

        expected_act,

        received_act

    )


# ==========================================================
# Demo
# ==========================================================

if __name__ == "__main__":

    pid = "PID-1001"

    nonce = b"1234567890123456"

    road = "RS-001"

    state = "ACTIVE"

    timestamp = 123456789

    act = generate_act(

        pid,

        nonce,

        road,

        state,

        timestamp

    )

    print("=" * 60)

    print("Authentication Confidence Token")

    print("=" * 60)

    print("ACT :", act)

    print(

        "Verified :",

        verify_act(

            act,

            pid,

            nonce,

            road,

            state,

            timestamp

        )

    )

    print("=" * 60)