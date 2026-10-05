"""
=========================================================
Man-in-the-Middle (MITM) Attack Evaluation Module
---------------------------------------------------------
Evaluates MITM resistance at two protocol layers:

1. Authentication-level MITM:
   The attacker intercepts M3 and modifies the ML-KEM ciphertext.
   The responder must reject M3 because the ML-DSA signature no
   longer matches the modified ciphertext.

2. Secure-message MITM:
   The attacker intercepts an encrypted application packet and
   modifies its ciphertext. The secure-message integrity check
   must reject the packet.

This module therefore tests the MITM property against the actual
M1-M4 authentication protocol as well as the established secure
communication channel.

Author : Meeth Amin
=========================================================
"""

import copy
import time

from models import Vehicle
from secure_messege_transfer import SecureMessageTransfer
from mutual_authentication import MutualAuthentication


class MITMAttack:
    """Man-in-the-Middle Attack Evaluation."""

    def __init__(
        self,
        secure_transfer: SecureMessageTransfer,
        authentication_manager: MutualAuthentication,
    ):
        self.secure_transfer = secure_transfer
        self.authentication_manager = authentication_manager

        self.total_attacks = 0
        self.detected_attacks = 0
        self.failed_detections = 0
        self.attack_times = []
        self.attack_logs = []

        print("\nMITM Attack Module Initialized")

    # =====================================================
    # Authentication-level MITM Test
    # =====================================================

    def execute_authentication_attack(
        self,
        sender: Vehicle,
        receiver,
    ):
        """
        Execute an MITM attack against the actual M1-M4 protocol.

        The attacker allows M1 and M2 to proceed normally, then
        intercepts M3 and modifies its ML-KEM ciphertext.

        Because the ciphertext is covered by the sender's ML-DSA
        signature, the responder must reject the modified M3.

        A fresh MutualAuthentication manager is used for this test
        so that the intentional failed M3 does not contaminate the
        normal Phase-7 authentication statistics.
        """

        print("\n" + "=" * 70)
        print("MITM ATTACK : M1-M4 AUTHENTICATION TEST")
        print("=" * 70)

        start = time.perf_counter()
        self.total_attacks += 1

        # -------------------------------------------------
        # Isolated authentication manager for the attack test
        # -------------------------------------------------

        # Use the same Trusted Authority as the real Phase-7
        # authentication manager, but keep a fresh authentication
        # manager for this intentional failed M3 test.
        auth_test = MutualAuthentication(
            self.authentication_manager.ta
        )

        try:
            # -------------------------------------------------
            # M1: Vehicle -> Responder
            # -------------------------------------------------

            print("\n[M1] Vehicle -> Responder")

            m1 = auth_test.create_auth_request(
                sender,
                receiver,
            )

            if not auth_test.verify_auth_request(
                receiver,
                m1,
            ):
                raise RuntimeError("M1 verification failed before MITM test")

            print("✓ M1 Verified")

            # -------------------------------------------------
            # M2: Responder -> Vehicle
            # -------------------------------------------------

            print("\n[M2] Responder -> Vehicle")

            m2 = auth_test.create_auth_response(
                receiver,
                sender,
            )

            if not auth_test.verify_auth_response(
                sender,
                receiver,
                m2,
            ):
                raise RuntimeError("M2 verification failed before MITM test")

            print("✓ M2 Verified")
            print("✓ Fresh M2 Challenge Generated")

            # -------------------------------------------------
            # M3: Vehicle -> Responder
            # -------------------------------------------------

            print("\n[M3] Vehicle -> Responder")

            m3_state = auth_test.create_m3_kem_message(
                sender,
                receiver,
                m1,
                m2,
            )

            original_m3 = m3_state["m3"]
            tampered_m3 = copy.deepcopy(original_m3)

            print("✓ Original M3 Generated")
            print("✓ M2 Challenge Nonce Bound to M3")
            print("✓ ML-DSA Signature Generated")

            # -------------------------------------------------
            # MITM interception
            # -------------------------------------------------

            print("\nMITM INTERCEPTION")
            print("-" * 70)
            print("Packet Intercepted : M3")
            print("Attacker Action     : Modify ML-KEM Ciphertext")

            ciphertext = bytearray(
                tampered_m3["ciphertext"]
            )

            if not ciphertext:
                raise RuntimeError("M3 ciphertext is empty")

            # Modify one byte of the transmitted ML-KEM ciphertext.
            ciphertext[0] ^= 0xFF
            tampered_m3["ciphertext"] = bytes(ciphertext)

            print("✗ M3 Ciphertext Modified by Attacker")
            print("✓ Original ML-DSA Signature Left Unchanged")
            print("\nResponder Processing Tampered M3...")

            # -------------------------------------------------
            # Responder processes tampered M3
            # -------------------------------------------------

            result = auth_test.process_m3_kem_message(
                sender,
                receiver,
                m1,
                m2,
                tampered_m3,
            )

            elapsed = (time.perf_counter() - start) * 1000
            self.attack_times.append(elapsed)

            # A modified ciphertext must cause M3 rejection.
            if result is None:
                self.detected_attacks += 1
                status = "BLOCKED"

                print("\n✓ MITM Attack Detected")
                print("✓ M3 Integrity Verification Failed")
                print("✓ Tampered M3 Rejected")
                print("✓ Session Key NOT Established")
                print("✓ Attack Successfully Blocked")
            else:
                self.failed_detections += 1
                status = "FAILED"

                print("\n✗ MITM Attack Was NOT Detected")
                print("✗ Tampered M3 Was Accepted")

        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            self.attack_times.append(elapsed)
            self.failed_detections += 1
            status = "FAILED"

            print("\n✗ MITM Authentication Test Failed")
            print(f"Reason : {exc}")

        self.attack_logs.append({
            "attack_type": "M3 authentication tampering",
            "sender": sender.real_id,
            "receiver": (
                receiver.rsu_id
                if hasattr(receiver, "rsu_id")
                else receiver.real_id
            ),
            "modified_field": "ML-KEM ciphertext",
            "status": status,
            "detection_time": elapsed,
            "timestamp": int(time.time()),
        })

        print(f"Detection Time : {elapsed:.3f} ms")

        return status == "BLOCKED"

    # =====================================================
    # Secure-message MITM Test
    # =====================================================

    def execute_attack(
        self,
        sender: Vehicle,
        receiver: Vehicle,
        packet,
    ):
        """
        Execute both MITM tests used by Phase 12.

        First, test tampering of the real M3 authentication message.
        Second, test tampering of an established secure-message packet.

        The existing main.py call therefore remains compatible.
        """

        # -------------------------------------------------
        # Test 1: M3 authentication tampering
        # -------------------------------------------------

        authentication_result = self.execute_authentication_attack(
            sender,
            receiver,
        )

        print("\n" + "=" * 70)
        print("MITM ATTACK : SECURE MESSAGE TEST")
        print("=" * 70)

        start = time.perf_counter()
        self.total_attacks += 1

        tampered_packet = copy.deepcopy(packet)

        print("Packet Intercepted")

        ciphertext = bytearray(
            tampered_packet["ciphertext"]
        )

        if not ciphertext:
            self.failed_detections += 1
            elapsed = (time.perf_counter() - start) * 1000
            self.attack_times.append(elapsed)
            print("✗ Empty Ciphertext - MITM Test Failed")
            return False

        ciphertext[0] ^= 0xFF
        tampered_packet["ciphertext"] = bytes(ciphertext)

        print("Ciphertext Modified")

        plaintext = self.secure_transfer.secure_receive(
            receiver,
            tampered_packet,
        )

        elapsed = (time.perf_counter() - start) * 1000
        self.attack_times.append(elapsed)

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

        self.attack_logs.append({
            "attack_type": "secure-message ciphertext tampering",
            "sender": sender.real_id,
            "receiver": receiver.real_id,
            "modified_field": "ciphertext",
            "status": status,
            "detection_time": elapsed,
            "timestamp": int(time.time()),
        })

        print(f"Detection Time : {elapsed:.3f} ms")

        return status == "BLOCKED"

    # =====================================================
    # Display Statistics
    # =====================================================

    def show_statistics(self):
        print("\n" + "=" * 70)
        print("MITM ATTACK STATISTICS")
        print("=" * 70)

        print(f"Total Attacks        : {self.total_attacks}")
        print(f"Detected Attacks     : {self.detected_attacks}")
        print(f"Failed Detections    : {self.failed_detections}")

        if self.attack_times:
            average = sum(self.attack_times) / len(self.attack_times)
        else:
            average = 0.0

        print(f"Average Detection Time : {average:.3f} ms")
        print("=" * 70)

    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):
        average = (
            sum(self.attack_times) / len(self.attack_times)
            if self.attack_times
            else 0.0
        )

        return {
            "total_attacks": self.total_attacks,
            "detected_attacks": self.detected_attacks,
            "failed_detections": self.failed_detections,
            "average_detection_time": average,
            "attack_times": self.attack_times.copy(),
            "attack_logs": self.attack_logs.copy(),
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
