"""
=========================================================
Context Manager
PQC-VANET Protocol

Purpose:
    Stores and manages the current
    vehicle operating context.
=========================================================
"""
from datetime import datetime

from common.protocol_types import (
    RoadType,
    PrivacyMode,
)

from common.models import (
    VehicleContext,
)


    # =========================================================
# Context Manager
# =========================================================

class ContextManager:
    """
    Manages the current vehicle context.

    Responsibilities:
        - Store current context
        - Update context
        - Return current context
    """

    def __init__(self, context: VehicleContext):
        """
        Initialize the Context Manager.
        """

        self._context = context
            # -----------------------------------------------------
    # Update Vehicle Context
    # -----------------------------------------------------

    def update_context(
        self,
        traffic_density: int = None,
        road_id: str = None,
        road_type: RoadType = None,
        vehicle_speed: float = None,
        security_alert: bool = None,
        rsu_trust_score: float = None,
        emergency_mode: bool = None,
        privacy_mode: PrivacyMode = None
    ):
        """
        Update only the supplied context values.
        """

        if traffic_density is not None:
            self._context.traffic_density = traffic_density

        if road_id is not None:
            self._context.road_id = road_id

        if road_type is not None:
            self._context.road_type = road_type

        if vehicle_speed is not None:
            self._context.vehicle_speed = vehicle_speed

        if security_alert is not None:
            self._context.security_alert = security_alert

        if rsu_trust_score is not None:
            self._context.rsu_trust_score = rsu_trust_score

        if emergency_mode is not None:
            self._context.emergency_mode = emergency_mode

        if privacy_mode is not None:
            self._context.privacy_mode = privacy_mode

        # Always update timestamp
        self._context.timestamp = datetime.now()
            # -----------------------------------------------------
    # Get Current Context
    # -----------------------------------------------------

    def get_context(self) -> VehicleContext:
        """
        Returns the current vehicle context.
        """

        return self._context


    # -----------------------------------------------------
    # Display Current Context
    # -----------------------------------------------------

    def display_context(self):
        """
        Display the current vehicle context.
        """

        print("\n")
        print("=" * 60)
        print("        CURRENT VEHICLE CONTEXT")
        print("=" * 60)

        print(f"Vehicle ID        : {self._context.vehicle_id}")
        print(f"Road ID           : {self._context.road_id}")
        print(f"Road Type         : {self._context.road_type.value}")
        print(f"Traffic Density   : {self._context.traffic_density}")
        print(f"Vehicle Speed     : {self._context.vehicle_speed:.2f} km/h")
        print(f"Security Alert    : {self._context.security_alert}")
        print(f"RSU Trust Score   : {self._context.rsu_trust_score:.2f}")
        print(f"Emergency Mode    : {self._context.emergency_mode}")
        print(f"Privacy Mode      : {self._context.privacy_mode.value}")
        print(f"Timestamp         : {self._context.timestamp}")

        print("=" * 60)
        print()
        # =========================================================
# Module Testing
# =========================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 60)
    print("      PQC-VANET CONTEXT MANAGER TEST")
    print("=" * 60)

    # -------------------------------------------------
    # Create Initial Vehicle Context
    # -------------------------------------------------

    context = VehicleContext(

        vehicle_id="V001",

        road_id="NH66",

        road_type=RoadType.HIGHWAY,

        traffic_density=2,

        vehicle_speed=80.0,

        security_alert=False,

        rsu_trust_score=0.95,

        emergency_mode=False,

        privacy_mode=PrivacyMode.NORMAL,

        timestamp=datetime.now()

    )

    # -------------------------------------------------
    # Initialize Context Manager
    # -------------------------------------------------

    manager = ContextManager(context)

    print("\nINITIAL CONTEXT")

    manager.display_context()

    # -------------------------------------------------
    # Simulate Context Change
    # -------------------------------------------------

    print("\nUpdating Vehicle Context...\n")

    manager.update_context(

        road_id="CITY-001",

        road_type=RoadType.CITY,

        traffic_density=5,

        vehicle_speed=42.0,

        security_alert=True,

        rsu_trust_score=0.35,

        privacy_mode=PrivacyMode.SECURE

    )

    print("UPDATED CONTEXT")

    manager.display_context()

    print("\n")

    print("=" * 60)

    print("Context Manager Test Completed Successfully")

    print("=" * 60)
