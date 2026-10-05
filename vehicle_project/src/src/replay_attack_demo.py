"""
=========================================================
Replay Attack Evaluation Module
---------------------------------------------------------
Evaluates replay attack resistance of the
PQC-VANET Protocol.

Attack Flow

Attacker
      ↓
Capture Secure Packet
      ↓
Replay Packet
      ↓
Replay Protection
      ↓
Attack Rejected

Author : Meeth Amin
=========================================================
"""

import copy
import time

from models import Vehicle

from secure_messege_transfer import SecureMessageTransfer


class ReplayAttack:

    """
    Replay Attack Evaluation Module
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        secure_transfer: SecureMessageTransfer
    ):

        self.secure_transfer = secure_transfer

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

        print("\nReplay Attack Module Initialized")
            # =====================================================
    # Execute Replay Attack
    # =====================================================

    def execute_attack(
        self,
        sender: Vehicle,
        receiver: Vehicle,
        packet
    ):
        """
        Execute a replay attack using a previously
        captured secure packet.
        """

        print("\n" + "=" * 70)
        print("REPLAY ATTACK EVALUATION")
        print("=" * 70)

        start = time.perf_counter()

        self.total_attacks += 1

        # -------------------------------------------------
        # Capture Original Packet
        # -------------------------------------------------

        captured_packet = copy.deepcopy(packet)

        print("Packet Captured Successfully")

        # -------------------------------------------------
        # Replay Packet
        # -------------------------------------------------

        print("Replaying Captured Packet...")

        plaintext = self.secure_transfer.secure_receive(

            receiver,

            captured_packet

        )

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

        if plaintext is None:

            self.detected_attacks += 1

            status = "BLOCKED"

            print("Replay Attack Detected")

            print("Attack Successfully Blocked")

        else:

            self.failed_detections += 1

            status = "FAILED"

            print("Replay Attack Was NOT Detected")

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.attack_logs.append({

            "sender":

                sender.real_id,

            "receiver":

                receiver.real_id,

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

        print("REPLAY ATTACK STATISTICS")

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

        print("Replay Attack Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"ReplayAttack("

            f"Total={self.total_attacks}, "

            f"Detected={self.detected_attacks}, "

            f"Failed={self.failed_detections})"

        )