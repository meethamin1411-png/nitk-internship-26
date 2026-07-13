"""
=========================================================
Certificateless Key Generation Protocol
---------------------------------------------------------
Generates certificateless cryptographic identities for
registered vehicles using the Trusted Authority.

Protocol Layer
=========================================================
"""

import time

from models import Vehicle
from models import TrustedAuthority


class CertificatelessKeyGeneration:

    """
    Certificateless Key Generation Protocol
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        trusted_authority: TrustedAuthority
    ):

        self.ta = trusted_authority

        # ---------------------------------------------
        # Performance Statistics
        # ---------------------------------------------

        self.key_generation_times = []

        self.total_generated = 0

        self.failed_requests = 0

        print(
            "\nCertificateless Key Generation Protocol Initialized"
        )
            # =====================================================
    # Generate Certificateless Keys
    # =====================================================

    def generate_keys(
        self,
        vehicle: Vehicle
    ):
        """
        Generate the complete certificateless identity
        for a registered vehicle.
        """

        print("\n" + "=" * 70)
        print("CERTIFICATELESS KEY GENERATION")
        print("=" * 70)

        start = time.perf_counter()

        # -------------------------------------------------
        # Registration Check
        # -------------------------------------------------

        if not self.ta.is_registered(vehicle.real_id):

            print("Vehicle is not registered.")

            self.failed_requests += 1

            return False

        # -------------------------------------------------
        # Generate Vehicle Secret
        # -------------------------------------------------

        vehicle.generate_secret_value()

        # -------------------------------------------------
        # Trusted Authority Issues Partial Keys
        # -------------------------------------------------

        self.ta.issue_partial_keys(vehicle)

        # -------------------------------------------------
        # Generate PQC Keys
        # -------------------------------------------------

        vehicle.initialize_crypto()

        # -------------------------------------------------
        # Store Public Keys
        # -------------------------------------------------

        self.ta.store_vehicle_keys(vehicle)

        end = time.perf_counter()

        elapsed = (end - start) * 1000

        self.key_generation_times.append(elapsed)

        self.total_generated += 1

        print(f"\nKey Generation Completed : {elapsed:.3f} ms")

        return True


    # =====================================================
    # Verify Generated Identity
    # =====================================================

    def verify_identity(
        self,
        vehicle: Vehicle
    ):
        """
        Verify that all required cryptographic
        material has been generated.
        """

        checks = [

            vehicle.secret_value,

            vehicle.partial_private_key,

            vehicle.partial_public_key,

            vehicle.partial_key_signature,

            vehicle.sig_pk,

            vehicle.sig_sk,

            vehicle.kem_pk,

            vehicle.kem_sk

        ]

        status = all(item is not None for item in checks)

        if status:

            print("✓ Vehicle Identity Verified")

        else:

            print("✗ Vehicle Identity Incomplete")

        return status
            # =====================================================
    # Generate Keys for Multiple Vehicles
    # =====================================================

    def generate_keys_for_all(
        self,
        vehicles
    ):
        """
        Generate certificateless identities for
        multiple registered vehicles.
        """

        print("\n" + "=" * 70)
        print("BULK CERTIFICATELESS KEY GENERATION")
        print("=" * 70)

        successful = 0

        failed = 0

        start = time.perf_counter()

        for vehicle in vehicles:

            if self.generate_keys(vehicle):

                successful += 1

            else:

                failed += 1

        total_time = (

            time.perf_counter() - start

        ) * 1000

        print("\n" + "=" * 70)

        print("KEY GENERATION SUMMARY")

        print("=" * 70)

        print(f"Successful : {successful}")

        print(f"Failed     : {failed}")

        print(f"Total Time : {total_time:.3f} ms")

        return successful


    # =====================================================
    # Verify All Vehicles
    # =====================================================

    def verify_all(
        self,
        vehicles
    ):
        """
        Verify certificateless identities
        for all vehicles.
        """

        verified = 0

        for vehicle in vehicles:

            if self.verify_identity(vehicle):

                verified += 1

        print(

            f"\nVerified "

            f"{verified}/{len(vehicles)} "

            f"Vehicles"

        )

        return verified
            # =====================================================
    # Average Key Generation Time
    # =====================================================

    def average_key_generation_time(self):
        """
        Return the average certificateless key
        generation time.
        """

        if not self.key_generation_times:

            return 0.0

        return (

            sum(self.key_generation_times)

            / len(self.key_generation_times)

        )


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.key_generation_times.clear()

        self.total_generated = 0

        self.failed_requests = 0

        print("Key Generation Statistics Reset")


    # =====================================================
    # Display Statistics
    # =====================================================

    def show_information(self):

        print("\n" + "=" * 70)

        print("CERTIFICATELESS KEY GENERATION")

        print("=" * 70)

        print(

            f"Generated Keys      : "

            f"{self.total_generated}"

        )

        print(

            f"Failed Requests     : "

            f"{self.failed_requests}"

        )

        print(

            f"Average Time        : "

            f"{self.average_key_generation_time():.3f} ms"

        )

        print(

            f"Recorded Executions : "

            f"{len(self.key_generation_times)}"

        )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        return {

            "generated_keys":
                self.total_generated,

            "failed_requests":
                self.failed_requests,

            "average_time":
                self.average_key_generation_time(),

            "key_generation_times":
                self.key_generation_times.copy()

        }
            # =====================================================
    # Protocol Summary
    # =====================================================

    def protocol_summary(self):

        print("\n" + "=" * 70)
        print("CERTIFICATELESS KEY GENERATION SUMMARY")
        print("=" * 70)

        print(f"Generated Vehicles      : {self.total_generated}")

        print(f"Failed Requests         : {self.failed_requests}")

        print(
            f"Average Generation Time : "
            f"{self.average_key_generation_time():.3f} ms"
        )

        print(
            f"Performance Records     : "
            f"{len(self.key_generation_times)}"
        )

        print("=" * 70)


    # =====================================================
    # Export Performance Data
    # =====================================================

    def export_performance_data(self):

        return {

            "total_generated":
                self.total_generated,

            "failed_requests":
                self.failed_requests,

            "average_generation_time":
                self.average_key_generation_time(),

            "records":
                len(self.key_generation_times),

            "times":
                self.key_generation_times.copy()

        }


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"CertificatelessKeyGeneration("

            f"Generated={self.total_generated}, "

            f"AverageTime={self.average_key_generation_time():.3f} ms)"

        )