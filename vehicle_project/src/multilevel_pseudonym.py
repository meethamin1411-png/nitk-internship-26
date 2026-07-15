"""
=========================================================
Multi-Level Pseudonym Generator
PQC-VANET Protocol

Purpose:
    Generates adaptive dynamic pseudonyms
    using QRNG, SHA3-256 and current
    vehicle context.
=========================================================
"""

from datetime import datetime
import hashlib

from crypto import qrng

from common.protocol_types import (
    PrivacyMode,
)

from common.models import (
    Pseudonym,
)

    # =========================================================
# Multi-Level Pseudonym Generator
# =========================================================

class MultiLevelPseudonymGenerator:
    """
    Generates dynamic pseudonyms using
    QRNG + SHA3-256.
    """

    def __init__(self):

        pass
            # -----------------------------------------------------
    # Generate Dynamic Pseudonym
    # -----------------------------------------------------

    def generate_pseudonym(
        self,
        vehicle_id: str,
        road_id: str,
        threat_level: str,
        privacy_mode: PrivacyMode
    ) -> Pseudonym:

        # ---------------------------------------------
        # Obtain Quantum Random Nonce
        # ---------------------------------------------

        qrng_nonce = qrng.generate_random_bytes(32)

        # ---------------------------------------------
        # Current Timestamp
        # ---------------------------------------------

        timestamp = datetime.now()

        # ---------------------------------------------
        # Build Input String
        # ---------------------------------------------

        input_data = (
            vehicle_id
            + road_id
            + threat_level
            + privacy_mode.value
            + timestamp.isoformat()
            + qrng_nonce.hex()
        )

        # ---------------------------------------------
        # Generate SHA3-256 PID
        # ---------------------------------------------

        pid = hashlib.sha3_256(
            input_data.encode()
        ).hexdigest()

        # ---------------------------------------------
        # Return Pseudonym Object
        # ---------------------------------------------

        return Pseudonym(
            pid=pid,
            privacy_mode=privacy_mode,
            created_at=timestamp,
            qrng_nonce=qrng_nonce
        )
        # =========================================================
# Module Testing
# =========================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 65)
    print("      PQC-VANET MULTI-LEVEL PSEUDONYM TEST")
    print("=" * 65)

    generator = MultiLevelPseudonymGenerator()

    # -----------------------------------------------------
    # Generate First Pseudonym
    # -----------------------------------------------------

    pseudonym1 = generator.generate_pseudonym(
        vehicle_id="V001",
        road_id="NH66",
        threat_level="HIGH",
        privacy_mode=PrivacyMode.SECURE
    )

    # -----------------------------------------------------
    # Generate Second Pseudonym
    # -----------------------------------------------------

    pseudonym2 = generator.generate_pseudonym(
        vehicle_id="V001",
        road_id="NH66",
        threat_level="HIGH",
        privacy_mode=PrivacyMode.SECURE
    )

    print("\nFirst Pseudonym")
    print("-" * 50)

    print(f"PID          : {pseudonym1.pid}")
    print(f"Mode         : {pseudonym1.privacy_mode.value}")
    print(f"Timestamp    : {pseudonym1.created_at}")
    print(f"QRNG Nonce   : {pseudonym1.qrng_nonce.hex()}")

    print("\nSecond Pseudonym")
    print("-" * 50)

    print(f"PID          : {pseudonym2.pid}")
    print(f"Mode         : {pseudonym2.privacy_mode.value}")
    print(f"Timestamp    : {pseudonym2.created_at}")
    print(f"QRNG Nonce   : {pseudonym2.qrng_nonce.hex()}")

    print("\n")

    if pseudonym1.pid != pseudonym2.pid:
        print("✅ SUCCESS : Dynamic Pseudonym Generation Verified")

    else:
        print("❌ ERROR : Duplicate Pseudonym Generated")

    print("\n")
    print("=" * 65)