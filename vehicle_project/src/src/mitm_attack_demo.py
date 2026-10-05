"""
=========================================================
Man-in-the-Middle (MITM) Attack Evaluation Module
---------------------------------------------------------
Evaluates MITM attack resistance of the
PQC-VANET Protocol.

Attack Flow

Vehicle
      ↓
Encrypted Packet
      ↓
Attacker Intercepts
      ↓
Ciphertext Modified
      ↓
Receiver
      ↓
Integrity Verification
      ↓
Attack Rejected

Author : Meeth Amin
=========================================================
"""

import copy
import time

from models import Vehicle

from secure_messege_transfer import SecureMessageTransfer


class MITMAttack:

    """
    Man-in-the-Middle Attack Evaluation
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

        print("\nMITM Attack Module Initialized")
            # =====================================================
    # Execute MITM Attack
    # =====================================================

    def execute_attack(
        self,
        sender: Vehicle,
        receiver: Vehicle,
        packet
    ):
        """
        Execute a Man-in-the-Middle attack by
        modifying the encrypted packet.
        """

        print("\n" + "=" * 70)
        print("MAN-IN-THE-MIDDLE ATTACK")
        print("=" * 70)

        start = time.perf_counter()

        self.total_attacks += 1

        # -------------------------------------------------
        # Copy Original Packet
        # -------------------------------------------------

        tampered_packet = copy.deepcopy(packet)

        print("Packet Intercepted")

        # -------------------------------------------------
        # Modify Ciphertext
        # -------------------------------------------------

        ciphertext = bytearray(

            tampered_packet["ciphertext"]

        )

        if len(ciphertext) > 0:

            ciphertext[0] ^= 0xFF

        tampered_packet["ciphertext"] = bytes(

            ciphertext

        )

        print("Ciphertext Modified")

        # -------------------------------------------------
        # Send Tampered Packet
        # -------------------------------------------------

        plaintext = self.secure_transfer.secure_receive(

            receiver,

            tampered_packet

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

            print("MITM Attack Detected")

            print("Integrity Verification Failed")

            print("Attack Successfully Blocked")

        else:

            self.failed_detections += 1

            status = "FAILED"

            print("MITM Attack Was NOT Detected")

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

        print("MITM ATTACK STATISTICS")

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

        print("MITM Attack Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"MITMAttack("

            f"Total={self.total_attacks}, "

            f"Detected={self.detected_attacks}, "

            f"Failed={self.failed_detections})"

        )