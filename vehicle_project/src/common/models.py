"""
=========================================================
Shared Data Models
PQC-VANET Protocol
=========================================================
"""

from dataclasses import dataclass
from datetime import datetime

from common.protocol_types import (
    RoadType,
    ThreatLevel,
    PrivacyMode,
    RotationReason,
)


# =========================================================
# Vehicle Context
# =========================================================

@dataclass
class VehicleContext:

    vehicle_id: str

    road_id: str

    road_type: RoadType

    traffic_density: int

    vehicle_speed: float

    security_alert: bool

    rsu_trust_score: float

    emergency_mode: bool

    privacy_mode: PrivacyMode

    timestamp: datetime


# =========================================================
# Threat Result
# =========================================================

@dataclass
class ThreatResult:

    score: int

    level: ThreatLevel

    reasons: list[str]


# =========================================================
# Generated Pseudonym
# =========================================================

@dataclass
class Pseudonym:

    pid: str

    privacy_mode: PrivacyMode

    created_at: datetime

    qrng_nonce: bytes


# =========================================================
# Managed Pseudonym
# =========================================================

@dataclass
class ManagedPseudonym:

    pid: str

    privacy_mode: PrivacyMode

    created_at: datetime

    expires_at: datetime | None = None

    rotation_reason: RotationReason = RotationReason.INITIAL_REGISTRATION