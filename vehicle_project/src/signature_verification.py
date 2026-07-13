"""
=========================================================
Signature Verification Manager
---------------------------------------------------------
Provides signature verification services for the
PQC-VANET Protocol.

Supports

• Authentication Verification
• Secure Message Verification
• Network Message Verification

Author : Meeth Amin
=========================================================
"""

import time

from digital_signature import DigitalSignature

from models import Vehicle
from models import RSU



class SignatureVerification:

    """
    Signature Verification Manager
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(self):

        self.signature_manager = DigitalSignature()

        # ==============================================
        # Statistics
        # ==============================================

        self.verification_times = []

        self.successful_verifications = 0

        self.failed_verifications = 0

        # ==============================================
        # Logs
        # ==============================================

        self.verification_logs = []

        print("\nSignature Verification Manager Initialized")
            # =====================================================
    # Verify Authentication Message
    # =====================================================

    def verify_authentication(
        self,
        sender,
        message,
        signature
    ):
        """
        Verify an authentication message signature.
        """

        print("\nVerifying Authentication Message...")

        start = time.perf_counter()

        status = self.signature_manager.verify(

            sender,

            message,

            signature

        )

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.verification_times.append(

            elapsed

        )

        if status:

            self.successful_verifications += 1

        else:

            self.failed_verifications += 1

        self.verification_logs.append({

            "type": "Authentication",

            "sender":

                sender.real_id

                if isinstance(sender, Vehicle)

                else sender.rsu_id,

            "status": status,

            "verification_time": elapsed,

            "timestamp": int(time.time())

        })

        return status


    # =====================================================
    # Verify Secure Message
    # =====================================================

    def verify_secure_message(
        self,
        sender,
        message,
        signature
    ):
        """
        Verify a secure VANET message.
        """

        print("\nVerifying Secure Message...")

        return self.verify_authentication(

            sender,

            message,

            signature

        )


    # =====================================================
    # Verify Network Message
    # =====================================================

    def verify_network_message(
        self,
        sender,
        message,
        signature
    ):
        """
        Verify a network communication message.
        """

        print("\nVerifying Network Message...")

        return self.verify_authentication(

            sender,

            message,

            signature

        )
            # =====================================================
    # Display Verification Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)
        print("SIGNATURE VERIFICATION STATISTICS")
        print("=" * 70)

        print(
            f"Successful Verifications : "
            f"{self.successful_verifications}"
        )

        print(
            f"Failed Verifications     : "
            f"{self.failed_verifications}"
        )

        print(
            f"Total Verifications      : "
            f"{len(self.verification_times)}"
        )

        if self.verification_times:

            average = (

                sum(self.verification_times)

                /

                len(self.verification_times)

            )

            print(
                f"Average Verification Time : "
                f"{average:.3f} ms"
            )

        else:

            print(
                "Average Verification Time : 0.000 ms"
            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        if self.verification_times:

            average = (

                sum(self.verification_times)

                /

                len(self.verification_times)

            )

        else:

            average = 0.0

        return {

            "successful":

                self.successful_verifications,

            "failed":

                self.failed_verifications,

            "average_time":

                average,

            "verification_times":

                self.verification_times.copy(),

            "verification_logs":

                self.verification_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.verification_times.clear()

        self.verification_logs.clear()

        self.successful_verifications = 0

        self.failed_verifications = 0

        print("Signature Verification Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"SignatureVerification("

            f"Success={self.successful_verifications}, "

            f"Failed={self.failed_verifications})"

        )