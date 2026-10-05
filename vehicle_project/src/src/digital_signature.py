"""
=========================================================
Digital Signature Manager
---------------------------------------------------------
Provides ML-DSA (Dilithium) based digital signatures
for the PQC-VANET protocol.

Supports

• Vehicle Signing
• RSU Signing
• Authentication Messages
• Secure Messages

Author : Meeth Amin
=========================================================
"""

import time

from crypto import dilithium

from models import Vehicle
from models import RSU


class DigitalSignature:

    """
    ML-DSA Digital Signature Manager
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(self):

        # ===============================================
        # Statistics
        # ===============================================

        self.signature_generation_times = []

        self.signature_verification_times = []

        self.successful_signatures = 0

        self.failed_verifications = 0

        # ===============================================
        # Logs
        # ===============================================

        self.signature_logs = []

        print("\nDigital Signature Manager Initialized")
            # =====================================================
    # Generate Digital Signature
    # =====================================================

    def sign(
        self,
        signer,
        message
    ):
        """
        Generate an ML-DSA (Dilithium) signature.

        Supports:
            Vehicle
            RSU
        """

        print("\nGenerating Digital Signature...")

        start = time.perf_counter()

        # ---------------------------------------------
        # Convert to Bytes
        # ---------------------------------------------

        if isinstance(message, str):

            message = message.encode()

        # ---------------------------------------------
        # Generate Signature
        # ---------------------------------------------

        signature = dilithium.sign_message(

            signer.sig_sk,

            message

        )

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        # ---------------------------------------------
        # Statistics
        # ---------------------------------------------

        self.signature_generation_times.append(

            elapsed

        )

        self.successful_signatures += 1

        # ---------------------------------------------
        # Logging
        # ---------------------------------------------

        self.signature_logs.append({

            "signer":

                signer.real_id

                if isinstance(signer, Vehicle)

                else signer.rsu_id,

            "timestamp":

                int(time.time()),

            "generation_time":

                elapsed

        })

        print("Digital Signature Generated")

        print(

            f"Generation Time : "

            f"{elapsed:.3f} ms"

        )

        return signature
            # =====================================================
    # Verify Digital Signature
    # =====================================================

    def verify(
        self,
        signer,
        message,
        signature
    ):
        """
        Verify an ML-DSA (Dilithium) signature.
        """

        print("\nVerifying Digital Signature...")

        start = time.perf_counter()

        if isinstance(message, str):

            message = message.encode()

        status = dilithium.verify_signature(

            signer.sig_pk,

            message,

            signature

        )

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.signature_verification_times.append(

            elapsed

        )

        if not status:

            self.failed_verifications += 1

            print("Signature Verification Failed")

            return False

        print("Signature Verified Successfully")

        print(

            f"Verification Time : "

            f"{elapsed:.3f} ms"

        )

        return True


    # =====================================================
    # Display Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)

        print("DIGITAL SIGNATURE STATISTICS")

        print("=" * 70)

        print(

            f"Successful Signatures   : "

            f"{self.successful_signatures}"

        )

        print(

            f"Failed Verifications    : "

            f"{self.failed_verifications}"

        )

        print(

            f"Generated Signatures    : "

            f"{len(self.signature_generation_times)}"

        )

        print(

            f"Verified Signatures     : "

            f"{len(self.signature_verification_times)}"

        )

        if self.signature_generation_times:

            avg_gen = (

                sum(self.signature_generation_times)

                /

                len(self.signature_generation_times)

            )

            print(

                f"Average Generation Time : "

                f"{avg_gen:.3f} ms"

            )

        if self.signature_verification_times:

            avg_ver = (

                sum(self.signature_verification_times)

                /

                len(self.signature_verification_times)

            )

            print(

                f"Average Verification Time : "

                f"{avg_ver:.3f} ms"

            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        return {

            "generation_times":

                self.signature_generation_times.copy(),

            "verification_times":

                self.signature_verification_times.copy(),

            "successful_signatures":

                self.successful_signatures,

            "failed_verifications":

                self.failed_verifications,

            "signature_logs":

                self.signature_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.signature_generation_times.clear()

        self.signature_verification_times.clear()

        self.signature_logs.clear()

        self.successful_signatures = 0

        self.failed_verifications = 0

        print("Digital Signature Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"DigitalSignature("

            f"Generated={self.successful_signatures}, "

            f"Failed={self.failed_verifications})"

        )