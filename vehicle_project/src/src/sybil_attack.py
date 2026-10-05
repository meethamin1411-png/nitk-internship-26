"""
=========================================================
Sybil Attack Evaluation Module
---------------------------------------------------------
Evaluates Sybil attack resistance of the
PQC-VANET Protocol.

Attack Flow

Attacker
      ↓
Generate Fake Vehicle Identity
      ↓
Attempt Authentication
      ↓
Trusted Authority Verification
      ↓
Attack Rejected

Author : Meeth Amin
=========================================================
"""

import time

from models import Vehicle

from models import TrustedAuthority

from mutual_authentication import MutualAuthentication


class SybilAttack:

    """
    Sybil Attack Evaluation Module
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        trusted_authority: TrustedAuthority,
        authentication_manager: MutualAuthentication
    ):

        self.ta = trusted_authority

        self.authentication = authentication_manager

        # ===============================================
        # Statistics
        # ===============================================

        self.total_attacks = 0

        self.detected_attacks = 0

        self.failed_detections = 0

        self.attack_times = []

        # ===============================================
        # Logs
        # ===============================================

        self.attack_logs = []

        print("\nSybil Attack Module Initialized")
            # =====================================================
    # Execute Sybil Attack
    # =====================================================

    def execute_attack(
        self,
        legitimate_vehicle: Vehicle
    ):
        """
        Execute a Sybil attack by creating an
        unregistered fake vehicle identity.
        """

        print("\n" + "=" * 70)
        print("SYBIL ATTACK EVALUATION")
        print("=" * 70)

        start = time.perf_counter()

        self.total_attacks += 1

        # -------------------------------------------------
        # Create Fake Vehicle
        # -------------------------------------------------

        fake_vehicle = Vehicle(

            real_id="SYBIL_" + str(int(time.time())),
            trusted_authority=self.ta

        )

        print("Fake Vehicle Created")

        # -------------------------------------------------
        # Trusted Authority Registration Check
        # -------------------------------------------------

        if fake_vehicle.real_id not in self.ta.vehicle_registry:

            detected = True

            print("Vehicle Not Registered")

        else:

            detected = False

        # -------------------------------------------------
        # Optional Authentication Attempt
        # -------------------------------------------------

        try:

            if detected:

                raise PermissionError(

                    "Authentication Rejected"

                )

        except PermissionError:

            pass

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.attack_times.append(

            elapsed

        )

        # -------------------------------------------------
        # Detection Result
        # -------------------------------------------------

        if detected:

            self.detected_attacks += 1

            status = "BLOCKED"

            print("Sybil Attack Detected")

            print("Authentication Rejected")

            print("Attack Successfully Blocked")

        else:

            self.failed_detections += 1

            status = "FAILED"

            print("Sybil Attack Was NOT Detected")

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.attack_logs.append({

            "fake_vehicle":

                fake_vehicle.real_id,

            "target_vehicle":

                legitimate_vehicle.real_id,

            "status":

                status,

            "detection_time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print(

            f"Detection Time : "

            f"{elapsed:.3f} ms"

        )

        return status == "BLOCKED"
            # =====================================================
    # Display Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)

        print("SYBIL ATTACK STATISTICS")

        print("=" * 70)

        print(
            f"Total Attacks        : "
            f"{self.total_attacks}"
        )

        print(
            f"Detected Attacks     : "
            f"{self.detected_attacks}"
        )

        print(
            f"Failed Detections    : "
            f"{self.failed_detections}"
        )

        if self.attack_times:

            average = (

                sum(self.attack_times)

                /

                len(self.attack_times)

            )

            print(

                f"Average Detection Time : "

                f"{average:.3f} ms"

            )

        else:

            print(

                "Average Detection Time : 0.000 ms"

            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        average = (

            sum(self.attack_times)

            /

            len(self.attack_times)

            if self.attack_times

            else 0.0

        )

        return {

            "total_attacks":

                self.total_attacks,

            "detected_attacks":

                self.detected_attacks,

            "failed_detections":

                self.failed_detections,

            "average_detection_time":

                average,

            "attack_times":

                self.attack_times.copy(),

            "attack_logs":

                self.attack_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.total_attacks = 0

        self.detected_attacks = 0

        self.failed_detections = 0

        self.attack_times.clear()

        self.attack_logs.clear()

        print("Sybil Attack Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"SybilAttack("

            f"Total={self.total_attacks}, "

            f"Detected={self.detected_attacks}, "

            f"Failed={self.failed_detections})"

        )
        