"""
=========================================================
Adaptive Multi-Level Pseudonym Generation

PQC-VANET Protocol

Author : Meeth Amin
=========================================================
"""

import time

from models import Vehicle
from models import TrustedAuthority

from common.protocol_types import (
    RoadType,
)

class PseudonymGeneration:
    """
    Adaptive Multi-Level Pseudonym Generation
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        trusted_authority: TrustedAuthority
    ):

        self.ta = trusted_authority

        # Statistics

        self.total_generated = 0

        self.failed_requests = 0

        self.generation_times = []

        self.pseudonym_logs = []

        print()

        print("=" * 65)

        print("Adaptive Multi-Level Pseudonym System Initialized")

        print("=" * 65)
            # =====================================================
    # Generate Adaptive Pseudonym
    # =====================================================

    def generate_pseudonym(
        self,
        vehicle: Vehicle
    ):
        """
        Generate an adaptive multi-level pseudonym
        for a registered vehicle.
        """

        print("\n" + "=" * 70)
        print("ADAPTIVE MULTI-LEVEL PSEUDONYM GENERATION")
        print("=" * 70)

        start = time.perf_counter()

        # -------------------------------------------------
        # Registration Check
        # -------------------------------------------------

        if not self.ta.is_registered(vehicle.real_id):

            print(f"❌ {vehicle.real_id} is not registered.")

            self.failed_requests += 1

            return False

            # -------------------------------------------------
        # Initialize Context
        # -------------------------------------------------

        if vehicle.real_id == "VEHICLE001":

            vehicle.initialize_context(

                road_id="NH66",

                road_type=RoadType.HIGHWAY,

                traffic_density=1,

                vehicle_speed=70,

                security_alert=False,

                rsu_trust_score=0.95,

                emergency_mode=False

            )

        else:

            vehicle.initialize_context(

                road_id="MILITARY_ZONE",

                road_type=RoadType.SENSITIVE_ZONE,

                traffic_density=5,

                vehicle_speed=120,

                security_alert=True,

                rsu_trust_score=0.20,

                emergency_mode=True

            )

        # -------------------------------------------------
        # Adaptive Pseudonym Generation
        # -------------------------------------------------

        vehicle.update_adaptive_pseudonym()

        pseudonym = vehicle.current_pseudonym

        # -------------------------------------------------
        # Update Trusted Authority
        # -------------------------------------------------

        self.ta.update_pseudonym(

            vehicle.real_id,

            pseudonym

        )

        # -------------------------------------------------
        # Performance
        # -------------------------------------------------

        elapsed = (

            time.perf_counter() - start

        ) * 1000

        self.total_generated += 1

        self.generation_times.append(elapsed)

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.pseudonym_logs.append({

            "vehicle": vehicle.real_id,

            "pseudonym": pseudonym,

            "privacy_mode":
                vehicle.current_privacy_mode.value,

            "threat_level":
                vehicle.current_threat.level.value,

            "generation_time": elapsed

        })

            # -------------------------------------------------
        # Display
        # -------------------------------------------------

        print()

        print("=" * 70)
        print("        ADAPTIVE MULTI-LEVEL PSEUDONYM REPORT")
        print("=" * 70)

        context = vehicle.context_manager.get_context()

        print("\nVEHICLE INFORMATION")
        print("-" * 70)
        print(f"Vehicle ID        : {vehicle.real_id}")

        print("\nCURRENT DRIVING CONTEXT")
        print("-" * 70)
        print(f"Road ID           : {context.road_id}")
        print(f"Road Type         : {context.road_type.value}")
        print(f"Traffic Density   : {context.traffic_density}/5")
        print(f"Vehicle Speed     : {context.vehicle_speed:.2f} km/h")
        print(f"Security Alert    : {context.security_alert}")
        print(f"RSU Trust Score   : {context.rsu_trust_score:.2f}")
        print(f"Emergency Mode    : {context.emergency_mode}")

        print("\nTHREAT EVALUATION")
        print("-" * 70)

        print(
            f"Threat Score      : "
            f"{vehicle.current_threat.score}/20"
        )

        print(
            f"Threat Level      : "
            f"{vehicle.current_threat.level.value}"
        )

        if vehicle.current_threat.level.value == "LOW":

            print("Risk Category     : SAFE")

        elif vehicle.current_threat.level.value == "MEDIUM":

            print("Risk Category     : CAUTION")

        else:

            print("Risk Category     : HIGH RISK")

        print("\nTHREAT ANALYSIS")
        print("-" * 70)

        for index, reason in enumerate(

            vehicle.current_threat.reasons,

            start=1

        ):

          print(f"{index}. {reason}")

        print("\nPRIVACY DECISION")
        print("-" * 70)

        print(
            f"Privacy Mode      : "
            f"{vehicle.current_privacy_mode.value}"
        )

        if vehicle.current_privacy_mode.value == "NORMAL":

            print("Privacy Level     : Standard Privacy")
            print("Generated Identity: PIDnormal")

        elif vehicle.current_privacy_mode.value == "PRIVACY":

            print("Privacy Level     : Enhanced Privacy")
            print("Generated Identity: PIDprivacy")

        else:

            print("Privacy Level     : Maximum Privacy Protection")
            print("Generated Identity: PIDsecure")

        print("\nADAPTIVE PSEUDONYM")
        print("-" * 70)
        print(pseudonym)

        print("\nPERFORMANCE")
        print("-" * 70)
        print(f"Generation Time   : {elapsed:.3f} ms")

        print("\nEXECUTION STATUS")
        print("-" * 70)
        print("✓ Context Evaluated")
        print("✓ Threat Score Calculated")
        print("✓ Privacy Policy Applied")
        print("✓ Adaptive Pseudonym Generated")
        print("✓ Trusted Authority Updated")

        print("=" * 70)
        return True
            # =====================================================
    # Generate Adaptive Pseudonyms for All Vehicles
    # =====================================================

    def generate_for_all(
        self,
        vehicles
    ):
        """
        Generate adaptive pseudonyms for all
        registered vehicles.
        """

        print("\n" + "=" * 70)
        print("ADAPTIVE BULK PSEUDONYM GENERATION")
        print("=" * 70)

        successful = 0

        failed = 0

        overall_start = time.perf_counter()

        for index, vehicle in enumerate(
            vehicles,
            start=1
        ):

            print()

            print("-" * 70)

            print(
                f"Vehicle {index}/{len(vehicles)}"
            )

            print("-" * 70)

            status = self.generate_pseudonym(
                vehicle
            )

            if status:

                successful += 1

            else:

                failed += 1

        total_time = (

            time.perf_counter()

            - overall_start

        ) * 1000

        print()

        print("=" * 70)

        print("ADAPTIVE PSEUDONYM GENERATION SUMMARY")

        print("=" * 70)

        print(f"Total Vehicles : {len(vehicles)}")

        print(f"Successful     : {successful}")

        print(f"Failed         : {failed}")

        print(f"Total Time     : {total_time:.3f} ms")

        print("=" * 70)

        return successful

            # =====================================================
    # Verify Adaptive Pseudonym
    # =====================================================

    def verify_pseudonym(
        self,
        vehicle: Vehicle
    ):
        """
        Verify that the vehicle has a valid
        adaptive pseudonym.
        """

        print()

        print("-" * 60)

        print(f"Verifying {vehicle.real_id}")

        print("-" * 60)

        if vehicle.current_pseudonym is None:

            print("Status : FAILED")

            print("Reason : No Pseudonym Found")

            return False

        if vehicle.current_threat is None:

            print("Status : FAILED")

            print("Reason : Threat Evaluation Missing")

            return False

        if vehicle.current_privacy_mode is None:

            print("Status : FAILED")

            print("Reason : Privacy Mode Missing")

            return False

        print("Status        : VERIFIED")

        print(f"Pseudonym     : {vehicle.current_pseudonym}")

        print(
            f"Threat Level  : "
            f"{vehicle.current_threat.level.value}"
        )

        print(
            f"Privacy Mode  : "
            f"{vehicle.current_privacy_mode.value}"
        )

        return True


    # =====================================================
    # Verify All Vehicles
    # =====================================================

    def verify_all(
        self,
        vehicles
    ):
        """
        Verify adaptive pseudonyms for all vehicles.
        """

        print("\n" + "=" * 70)

        print("VERIFYING ADAPTIVE PSEUDONYMS")

        print("=" * 70)

        verified = 0

        for vehicle in vehicles:

            if self.verify_pseudonym(vehicle):

                verified += 1

        print()

        print("=" * 70)

        print(
            f"Verified Vehicles : {verified}/{len(vehicles)}"
        )

        print("=" * 70)

        return verified
            # =====================================================
    # Display Information
    # =====================================================

    def show_information(self):
        """
        Display Adaptive Multi-Level Pseudonym
        Generation statistics.
        """

        print("\n" + "=" * 70)

        print("ADAPTIVE MULTI-LEVEL PSEUDONYM INFORMATION")

        print("=" * 70)

        print(
            f"Generated Pseudonyms : {self.total_generated}"
        )

        print(
            f"Failed Requests      : {self.failed_requests}"
        )

        if self.generation_times:

            average = (

                sum(self.generation_times)

                / len(self.generation_times)

            )

        else:

            average = 0.0

        print(
            f"Average Time         : {average:.3f} ms"
        )

        print(
            f"Performance Records  : {len(self.generation_times)}"
        )

        print("=" * 70)


    # =====================================================
    # Statistics
    # =====================================================

    def get_statistics(self):
        """
        Return protocol statistics.
        """

        if self.generation_times:

            average = (

                sum(self.generation_times)

                / len(self.generation_times)

            )

        else:

            average = 0.0

        return {

            "generated": self.total_generated,

            "failed": self.failed_requests,

            "average_generation_time": average,

            "generation_times": self.generation_times.copy(),

            "logs": self.pseudonym_logs.copy()

        }


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"PseudonymGeneration("

            f"Generated={self.total_generated}, "

            f"Failed={self.failed_requests})"

        )
            # =====================================================
    # Trace Pseudonym
    # =====================================================

    def trace_pseudonym(
        self,
        pseudonym
    ):
        """
        Trace a pseudonym back to the
        original registered vehicle.
        """

        vehicle = self.ta.get_vehicle_by_pseudonym(
            pseudonym
        )

        if vehicle is None:

            print("Pseudonym Not Found")

            return None

        print()

        print("=" * 70)

        print("PSEUDONYM TRACE")

        print("=" * 70)

        print(f"Pseudonym : {pseudonym}")

        print(f"Vehicle ID : {vehicle.real_id}")

        print("=" * 70)

        return vehicle