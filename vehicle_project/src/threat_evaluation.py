"""
=========================================================
Threat Evaluation Module
PQC-VANET Protocol

Purpose:
    Evaluates the current driving environment and
    determines the threat level for adaptive
    multi-level pseudonym generation.
=========================================================
"""
from datetime import datetime

from common.protocol_types import (
    ThreatLevel,
    RoadType,
    PrivacyMode
)

from common.models import (
    VehicleContext,
    ThreatResult
)

    # =========================================================
# Threat Evaluation Engine
# =========================================================

class ThreatEvaluation:
    """
    Threat Evaluation Engine

    This class evaluates the vehicle's current
    operating environment and computes the
    corresponding threat score and threat level.
    """

    def __init__(self):
        """
        Initialize Threat Evaluation Engine.
        """
        pass
            # -----------------------------------------------------
    # Calculate Threat Score
    # -----------------------------------------------------

    def calculate_threat_score(self, context: VehicleContext):
        """
        Calculate the overall threat score based on
        the current vehicle context.

        Returns:
            tuple:
                (score, reasons)
        """

        score = 0
        reasons = []

        # ==========================================
        # Traffic Density
        # ==========================================

        score += context.traffic_density

        if context.traffic_density >= 4:
            reasons.append("High Traffic Density")

        # ==========================================
        # Road Type
        # ==========================================

        road_scores = {
            RoadType.HIGHWAY: 0,
            RoadType.CITY: 1,
            RoadType.INTERSECTION: 2,
            RoadType.SENSITIVE_ZONE: 3
        }

        road_score = road_scores.get(context.road_type, 0)

        score += road_score

        if road_score > 0:
            reasons.append(
                f"Road Type: {context.road_type.value}"
            )

        # ==========================================
        # Vehicle Speed
        # ==========================================

        if context.vehicle_speed > 100:

            score += 2

            reasons.append(
                "High Vehicle Speed"
            )

        # ==========================================
        # Security Alert
        # ==========================================

        if context.security_alert:

            score += 5

            reasons.append(
                "Security Alert Active"
            )

        # ==========================================
        # RSU Trust
        # ==========================================

        if context.rsu_trust_score < 0.40:

            score += 3

            reasons.append(
                "Low RSU Trust"
            )

        elif context.rsu_trust_score < 0.70:

            score += 1

            reasons.append(
                "Medium RSU Trust"
            )

        # ==========================================
        # Emergency Mode
        # ==========================================

        if context.emergency_mode:

            score += 5

            reasons.append(
                "Emergency Mode Enabled"
            )
        return score, reasons
            # -----------------------------------------------------
    # Evaluate Threat Level
    # -----------------------------------------------------

    def evaluate(self, context: VehicleContext) -> ThreatResult:
        """
        Evaluate the complete threat level.

        Parameters
        ----------
        context : VehicleContext
            Current vehicle operating context.

        Returns
        -------
        ThreatResult
            Final threat evaluation.
        """

        score, reasons = self.calculate_threat_score(context)

        # ==========================================
        # Determine Threat Level
        # ==========================================

        if score <= 6:

            level = ThreatLevel.LOW

        elif score <= 13:

            level = ThreatLevel.MEDIUM

        else:

            level = ThreatLevel.HIGH

        return ThreatResult(
            score=score,
            level=level,
            reasons=reasons
        )
        # =========================================================
# Module Testing
# =========================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 60)
    print("      PQC-VANET THREAT EVALUATION TEST")
    print("=" * 60)

    # ---------------------------------------------
    # Sample Vehicle Context
    # ---------------------------------------------

    context = VehicleContext(

    vehicle_id="V001",

    road_id="CITY-001",

    road_type=RoadType.SENSITIVE_ZONE,

    traffic_density=5,

    vehicle_speed=110.0,

    security_alert=True,

    rsu_trust_score=0.30,

    emergency_mode=False,

    privacy_mode=PrivacyMode.SECURE,

    timestamp=datetime.now()

)

    # ---------------------------------------------
    # Run Threat Evaluation
    # ---------------------------------------------

    engine = ThreatEvaluation()

    result = engine.evaluate(context)

    # ---------------------------------------------
    # Display Result
    # ---------------------------------------------

    print(f"\nThreat Score : {result.score}")

    print(f"Threat Level : {result.level.value}")

    print("\nReasons:")

    for reason in result.reasons:

        print(f"  ✓ {reason}")

    print("\n")

    print("=" * 60)