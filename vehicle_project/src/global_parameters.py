"""
=============================================================
PQC-VANET Global Parameters
-------------------------------------------------------------
This module defines all global system parameters used
throughout the Post-Quantum Certificateless VANET.

Author : Meeth Amin
=============================================================
"""

from dataclasses import dataclass
from typing import Tuple
import hashlib


@dataclass(frozen=True)
class GlobalParameters:
    """
    Global configuration for the PQC-VANET system.
    """

    # ==========================================================
    # System Information
    # ==========================================================

    SYSTEM_NAME: str = "PQC-VANET"

    VERSION: str = "1.0"

    SECURITY_LEVEL: str = "NIST Level-3"

    # ==========================================================
    # Cryptographic Algorithms
    # ==========================================================

    SIGNATURE_SCHEME: str = "ML-DSA-65 (Dilithium)"

    KEM_SCHEME: str = "ML-KEM-768 (Kyber)"

    HASH_FUNCTION = hashlib.sha3_256

    SESSION_KEY_LENGTH: int = 32      # 256-bit

    NONCE_LENGTH: int = 32

    RANDOM_SEED_LENGTH: int = 32

    # ==========================================================
    # Authentication Parameters
    # ==========================================================

    TIMESTAMP_WINDOW: int = 5000
    """
    milliseconds
    Replay packets older than 5 seconds are rejected.
    """

    MAX_FAILED_ATTEMPTS: int = 5

    PSEUDONYM_VALIDITY: int = 300
    """
    Seconds
    Pseudonym changes every 5 minutes.
    """

    # ==========================================================
    # Vehicle Parameters
    # ==========================================================

    MAX_SPEED = 120      # km/h

    MIN_SPEED = 0

    COMMUNICATION_RANGE = 300      # meters

    VEHICLE_BUFFER_SIZE = 1024

    # ==========================================================
    # RSU Parameters
    # ==========================================================

    RSU_RANGE = 500

    MAX_CONNECTED_VEHICLES = 100

    # ==========================================================
    # City Simulation
    # ==========================================================

    CITY_WIDTH = 5000

    CITY_HEIGHT = 5000

    LANE_WIDTH = 3.5

    NUMBER_OF_RSU = 2

    NUMBER_OF_VEHICLES = 20

    # ==========================================================
    # Performance Evaluation
    # ==========================================================

    LOG_DIRECTORY = "results"

    REGISTRATION_LOG = "registration.csv"

    AUTH_LOG = "authentication.csv"

    PSEUDONYM_LOG = "pseudonym.csv"

    SIGNATURE_LOG = "signature.csv"

    VERIFY_LOG = "verification.csv"

    SESSION_LOG = "session.csv"

    COMMUNICATION_LOG = "communication.csv"

    # ==========================================================
    # QRNG Configuration
    # ==========================================================

    USE_QRNG = False
    """
    False → os.urandom()

    True → Quantum RNG
    """

    QRNG_PROVIDER = "LOCAL"

    # ==========================================================
    # Attack Simulation
    # ==========================================================

    ENABLE_REPLAY_TEST = True

    ENABLE_MITM_TEST = True

    ENABLE_SYBIL_TEST = True

    # ==========================================================
    # Traceability
    # ==========================================================

    ENABLE_TRACEABILITY = True


GLOBAL = GlobalParameters()


# ==============================================================
# Helper Functions
# ==============================================================

def session_context(id1: str, id2: str) -> bytes:
    """
    Generate unique session context.
    """

    if id1 < id2:

        context = id1 + id2

    else:

        context = id2 + id1

    return context.encode()


def within_timestamp(current, received):

    return abs(current - received) <= GLOBAL.TIMESTAMP_WINDOW


def communication_possible(distance):

    return distance <= GLOBAL.COMMUNICATION_RANGE


def rsu_reachable(distance):

    return distance <= GLOBAL.RSU_RANGE