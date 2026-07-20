"""
=========================================================
Threat Evaluation Module
PQC-VANET Protocol

Purpose:
    Evaluates the current driving context and
    determines the threat score, threat level,
    and risk category for adaptive pseudonym
    generation.
=========================================================
"""

from common.protocol_types import (
    ThreatLevel,
    RoadType,
)

from common.models import (
    VehicleContext,
    ThreatResult,
)
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List
from enum import Enum
# =========================================================
# Threat Evaluation Engine
# =========================================================

class ThreatEvaluation:
    """
    Adaptive Threat Evaluation Engine.

    This module analyses the vehicle's current
    driving environment and computes the threat
    score used by the adaptive privacy policy.
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(self):

        # =====================================================
        # Existing Configuration
        # =====================================================

        self.maximum_score = 20

        # =====================================================
        # Vehicle Threat Database
        # =====================================================

        self.vehicle_database: Dict[str, VehicleThreatRecord] = {}

        # =====================================================
        # Research Statistics
        # =====================================================

        self.total_registered = 0

        self.total_events = 0

        self.event_statistics = {
            "Traffic Density": 0,
            "Road Type": 0,
            "High Speed": 0,
            "Security Alert": 0,
            "Low RSU Trust": 0,
            "Emergency Mode": 0
        }

        print()
        print("=" * 65)
        print("Threat Evaluation Engine V2 Initialized")
        print("=" * 65)

    # =====================================================
    # Register Vehicle
    # =====================================================

    def register_vehicle(self, vehicle_id):

        if vehicle_id not in self.vehicle_database:

            self.vehicle_database[vehicle_id] = VehicleThreatRecord(
                vehicle_id
            )

            self.total_registered += 1

# =====================================================
# Get Vehicle Record
# =====================================================

    def get_vehicle_record(self, vehicle_id):

      return self.vehicle_database.get(vehicle_id)
    # =====================================================
    # Calculate Threat Score
    # =====================================================

    def calculate_threat_score(
        self,
        context: VehicleContext
    ):
        """
        Calculate the threat score based on
        the current driving context.

        Returns
        -------
        tuple
            (score, reasons)
        """

        score = 0

        reasons = []

        # ==================================================
        # Traffic Density
        # ==================================================

        score += context.traffic_density

        if context.traffic_density >= 4:

            reasons.append(
                f"High Traffic Density ({context.traffic_density}/5)"
            )

        elif context.traffic_density >= 2:

            reasons.append(
                f"Moderate Traffic Density ({context.traffic_density}/5)"
            )

        else:

            reasons.append(
                f"Low Traffic Density ({context.traffic_density}/5)"
            )

        # ==================================================
        # Road Type
        # ==================================================

        road_score = {

            RoadType.HIGHWAY: 0,

            RoadType.CITY: 1,

            RoadType.INTERSECTION: 2,

            RoadType.SENSITIVE_ZONE: 3

        }.get(context.road_type, 0)

        score += road_score

        if context.road_type == RoadType.HIGHWAY:

            reasons.append("Highway Environment")

        elif context.road_type == RoadType.CITY:

            reasons.append("Urban City Road")

        elif context.road_type == RoadType.INTERSECTION:

            reasons.append("Busy Road Intersection")

        elif context.road_type == RoadType.SENSITIVE_ZONE:

            reasons.append("Sensitive Security Zone")

        # ==================================================
        # Vehicle Speed
        # ==================================================

        if context.vehicle_speed >= 100:

            score += 2

            reasons.append(
                f"High Vehicle Speed ({context.vehicle_speed:.0f} km/h)"
            )

        else:

            reasons.append(
                f"Normal Vehicle Speed ({context.vehicle_speed:.0f} km/h)"
            )

        # ==================================================
        # Security Alert
        # ==================================================

        if context.security_alert:

            score += 5

            reasons.append(
                "Active Security Alert Detected"
            )

        else:

            reasons.append(
                "No Active Security Alert"
            )

        # ==================================================
        # RSU Trust
        # ==================================================

        if context.rsu_trust_score < 0.40:

            score += 3

            reasons.append(
                f"Low RSU Trust ({context.rsu_trust_score:.2f})"
            )

        elif context.rsu_trust_score < 0.70:

            score += 1

            reasons.append(
                f"Medium RSU Trust ({context.rsu_trust_score:.2f})"
            )

        else:

            reasons.append(
                f"High RSU Trust ({context.rsu_trust_score:.2f})"
            )

        # ==================================================
        # Emergency Mode
        # ==================================================

        if context.emergency_mode:

            score += 5

            reasons.append(
                "Emergency Vehicle Mode Enabled"
            )

        else:

            reasons.append(
                "Normal Driving Mode"
            )

        return score, reasons
            # =====================================================
    # Evaluate Threat
    # =====================================================

    def evaluate(
        self,
        context: VehicleContext
    ) -> ThreatResult:
        """
        Evaluate the complete threat level.

        Parameters
        ----------
        context : VehicleContext
            Current vehicle context.

        Returns
        -------
        ThreatResult
            Final threat evaluation result.
        """

        # ---------------------------------------------
        # Calculate Threat Score
        # ---------------------------------------------

        score, reasons = self.calculate_threat_score(
            context
        )

        # ---------------------------------------------
        # Determine Threat Level
        # ---------------------------------------------

        if score <= 6:

            level = ThreatLevel.LOW

        elif score <= 13:

            level = ThreatLevel.MEDIUM

        else:

            level = ThreatLevel.HIGH

        # ---------------------------------------------
        # Return Result
        # ---------------------------------------------

        return ThreatResult(

            score=score,

            level=level,

            reasons=reasons

        )
            # =====================================================
    # Display Threat Report
    # =====================================================

    def display_report(
        self,
        result: ThreatResult
    ):
        """
        Display a formatted threat evaluation report.
        """

        print("\n")
        print("=" * 65)
        print("            THREAT EVALUATION REPORT")
        print("=" * 65)

        print(f"Threat Score    : {result.score}/{self.maximum_score}")
        print(f"Threat Level    : {result.level.value}")

        if result.level == ThreatLevel.LOW:

            print("Risk Category   : SAFE")

        elif result.level == ThreatLevel.MEDIUM:

            print("Risk Category   : CAUTION")

        else:

            print("Risk Category   : HIGH RISK")

        print("\nThreat Analysis")
        print("-" * 65)

        for index, reason in enumerate(

            result.reasons,

            start=1

        ):

            print(f"{index}. {reason}")

        print("=" * 65)
        # =====================================================
# Module Testing
# =====================================================

if __name__ == "__main__":

    from datetime import datetime

    engine = ThreatEvaluation()

    context = VehicleContext(

        vehicle_id="VEHICLE001",

        road_id="MILITARY_ZONE",

        road_type=RoadType.SENSITIVE_ZONE,

        traffic_density=5,

        vehicle_speed=120,

        security_alert=True,

        rsu_trust_score=0.20,

        emergency_mode=True,

        privacy_mode=None,

        timestamp=datetime.now()

    )

    result = engine.evaluate(context)

    engine.display_report(result)