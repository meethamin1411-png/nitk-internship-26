"""
=========================================================
Pseudonym Generation Protocol
---------------------------------------------------------
Provides conditional privacy for vehicles by replacing
their real identities with temporary pseudonyms.

Protocol Flow

Vehicle
     ↓
QRNG Nonce
     ↓
Timestamp
     ↓
SHA3-256 Hash
     ↓
Temporary Pseudonym
     ↓
Trusted Authority Mapping

Author : Meeth Amin
=========================================================
"""

import time
import hashlib

from crypto import qrng

from models import Vehicle
from models import TrustedAuthority


class PseudonymGeneration:

    """
    Pseudonym Generation Manager
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        trusted_authority: TrustedAuthority
    ):

        self.ta = trusted_authority

        # ==============================================
        # Statistics
        # ==============================================

        self.total_generated = 0

        self.failed_requests = 0

        self.generation_times = []

        # ==============================================
        # Logs
        # ==============================================

        self.pseudonym_logs = []

        print(

            "\nPseudonym Generation Protocol Initialized"

        )
            # =====================================================
    # Generate Pseudonym
    # =====================================================

    def generate_pseudonym(
        self,
        vehicle: Vehicle
    ):
        """
        Generate a temporary pseudonym for a
        registered vehicle.
        """

        print("\n" + "=" * 70)
        print("PSEUDONYM GENERATION")
        print("=" * 70)

        start = time.perf_counter()

        # -------------------------------------------------
        # Registration Check
        # -------------------------------------------------

        if not self.ta.is_registered(

            vehicle.real_id

        ):

            print("Vehicle is not registered.")

            self.failed_requests += 1

            return False

        # -------------------------------------------------
        # Generate QRNG Nonce
        # -------------------------------------------------

        nonce = qrng.generate_random_bytes(

            16

        )

        # -------------------------------------------------
        # Current Timestamp
        # -------------------------------------------------

        timestamp = str(

            int(time.time() * 1000)

        )

        # -------------------------------------------------
        # SHA3-256 Pseudonym
        # -------------------------------------------------

        pseudonym = hashlib.sha3_256(

            vehicle.real_id.encode()

            + nonce

            + timestamp.encode()

        ).hexdigest()[:24]

        # -------------------------------------------------
        # Update Vehicle
        # -------------------------------------------------

        vehicle.previous_pseudonym = (

            vehicle.current_pseudonym

        )

        vehicle.current_pseudonym = pseudonym

        vehicle.pseudonym_count += 1

        # -------------------------------------------------
        # Update Trusted Authority
        # -------------------------------------------------

        self.ta.update_pseudonym(

            vehicle.real_id,

            pseudonym

        )

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.generation_times.append(

            elapsed

        )

        self.total_generated += 1

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.pseudonym_logs.append({

            "vehicle":

                vehicle.real_id,

            "pseudonym":

                pseudonym,

            "generation_time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print(

            f"Vehicle ID : {vehicle.real_id}"

        )

        print(

            f"Pseudonym : {pseudonym}"

        )

        print(

            f"Generation Time : "

            f"{elapsed:.3f} ms"

        )

        return True
            # =====================================================
    # Generate Pseudonyms for All Vehicles
    # =====================================================

    def generate_for_all(
        self,
        vehicles
    ):
        """
        Generate pseudonyms for all registered vehicles.
        """

        print("\n" + "=" * 70)
        print("BULK PSEUDONYM GENERATION")
        print("=" * 70)

        successful = 0

        failed = 0

        start = time.perf_counter()

        for vehicle in vehicles:

            if self.generate_pseudonym(vehicle):

                successful += 1

            else:

                failed += 1

        total_time = (

            time.perf_counter()

            - start

        ) * 1000

        print("\n" + "=" * 70)

        print("PSEUDONYM GENERATION SUMMARY")

        print("=" * 70)

        print(f"Successful : {successful}")

        print(f"Failed     : {failed}")

        print(f"Total Time : {total_time:.3f} ms")

        return successful


    # =====================================================
    # Verify Pseudonym
    # =====================================================

    def verify_pseudonym(
        self,
        vehicle: Vehicle
    ):
        """
        Verify that a vehicle has a valid pseudonym.
        """

        if vehicle.current_pseudonym is None:

            print(

                f"{vehicle.real_id} : No Pseudonym"

            )

            return False

        print(

            f"{vehicle.real_id} : Pseudonym Verified"

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
        Verify pseudonyms for all vehicles.
        """

        verified = 0

        for vehicle in vehicles:

            if self.verify_pseudonym(vehicle):

                verified += 1

        print(

            f"\nVerified "

            f"{verified}/{len(vehicles)} "

            f"Vehicles"

        )

        return verified


    # =====================================================
    # Trace Pseudonym
    # =====================================================

    def trace_pseudonym(
        self,
        pseudonym
    ):
        """
        Trace a pseudonym back to the real vehicle.
        """

        vehicle = self.ta.get_vehicle_by_pseudonym(

            pseudonym

        )

        if vehicle is None:

            print(

                "Pseudonym Not Found"

            )

            return None

        print(

            f"Pseudonym belongs to : "

            f"{vehicle.real_id}"

        )

        return vehicle
            # =====================================================
    # Average Generation Time
    # =====================================================

    def average_generation_time(self):
        """
        Return the average pseudonym generation time.
        """

        if not self.generation_times:

            return 0.0

        return (

            sum(self.generation_times)

            / len(self.generation_times)

        )


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):
        """
        Reset all performance statistics.
        """

        self.total_generated = 0

        self.failed_requests = 0

        self.generation_times.clear()

        self.pseudonym_logs.clear()

        print(

            "Pseudonym Generation Statistics Reset"

        )


    # =====================================================
    # Display Information
    # =====================================================

    def show_information(self):

        print("\n" + "=" * 70)

        print("PSEUDONYM GENERATION INFORMATION")

        print("=" * 70)

        print(

            f"Generated Pseudonyms : "

            f"{self.total_generated}"

        )

        print(

            f"Failed Requests      : "

            f"{self.failed_requests}"

        )

        print(

            f"Average Time         : "

            f"{self.average_generation_time():.3f} ms"

        )

        print(

            f"Recorded Executions  : "

            f"{len(self.generation_times)}"

        )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        return {

            "generated":

                self.total_generated,

            "failed":

                self.failed_requests,

            "average_time":

                self.average_generation_time(),

            "generation_times":

                self.generation_times.copy(),

            "logs":

                self.pseudonym_logs.copy()

        }


    # =====================================================
    # Protocol Summary
    # =====================================================

    def protocol_summary(self):

        print("\n" + "=" * 70)

        print("PSEUDONYM GENERATION SUMMARY")

        print("=" * 70)

        print(

            f"Generated Pseudonyms : "

            f"{self.total_generated}"

        )

        print(

            f"Failed Requests      : "

            f"{self.failed_requests}"

        )

        print(

            f"Average Time         : "

            f"{self.average_generation_time():.3f} ms"

        )

        print(

            f"Performance Records  : "

            f"{len(self.generation_times)}"

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

                self.average_generation_time(),

            "records":

                len(self.generation_times),

            "times":

                self.generation_times.copy()

        }


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"PseudonymGeneration("

            f"Generated={self.total_generated}, "

            f"AverageTime={self.average_generation_time():.3f} ms)"

        )