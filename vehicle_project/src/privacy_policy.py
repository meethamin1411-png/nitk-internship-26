"""
=========================================================
Privacy Policy
PQC-VANET Protocol

Maps threat levels to privacy modes.
=========================================================
"""

from common.protocol_types import (
    ThreatLevel,
    PrivacyMode,
)


class PrivacyPolicy:
    """
    Determines the appropriate privacy mode
    based on the current threat level.
    """

    @staticmethod
    def select_privacy_mode(
        threat_level: ThreatLevel
    ) -> PrivacyMode:

        if threat_level == ThreatLevel.HIGH:
            return PrivacyMode.SECURE

        elif threat_level == ThreatLevel.MEDIUM:
            return PrivacyMode.PRIVACY

        else:
            return PrivacyMode.NORMAL