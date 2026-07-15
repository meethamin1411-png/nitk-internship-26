"""
=========================================================
Common Types
PQC-VANET Protocol

Shared enums used across the protocol.
=========================================================
"""

from enum import Enum


# =========================================================
# Threat Level
# =========================================================

class ThreatLevel(Enum):

    LOW = "LOW"

    MEDIUM = "MEDIUM"

    HIGH = "HIGH"


# =========================================================
# Privacy Mode
# =========================================================

class PrivacyMode(Enum):

    NORMAL = "NORMAL"

    PRIVACY = "PRIVACY"

    SECURE = "SECURE"


# =========================================================
# Road Type
# =========================================================

class RoadType(Enum):

    HIGHWAY = "HIGHWAY"

    CITY = "CITY"

    INTERSECTION = "INTERSECTION"

    SENSITIVE_ZONE = "SENSITIVE_ZONE"


# =========================================================
# Rotation Reason
# =========================================================

class RotationReason(Enum):

    INITIAL_REGISTRATION = "Initial Registration"

    AUTHENTICATION = "Authentication"

    CONTEXT_CHANGE = "Context Change"

    THREAT_CHANGE = "Threat Change"

    MANUAL = "Manual"