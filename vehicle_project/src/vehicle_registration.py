"""
=========================================================
Vehicle Registration Protocol
---------------------------------------------------------
Handles secure registration of Vehicles and RSUs
using the Trusted Authority.

Protocol Layer
=========================================================
"""

import time

from models import Vehicle
from models import RSU
from models import TrustedAuthority


class VehicleRegistration:

    """
    Registration Protocol
    """

    def __init__(

        self,

        trusted_authority: TrustedAuthority

    ):

        self.ta = trusted_authority

        # ------------------------------------------
        # Performance Logs
        # ------------------------------------------

        self.registration_times = []

        self.total_registered = 0

        print("\nVehicle Registration Protocol Initialized")
            # =====================================================
    # Register Vehicle
    # =====================================================

    def register_vehicle(
        self,
        vehicle: Vehicle
    ):

        print("\n" + "=" * 70)
        print("VEHICLE REGISTRATION PROTOCOL")
        print("=" * 70)

        start = time.perf_counter()

        # ------------------------------------------
        # Vehicle Local Registration
        # ------------------------------------------

        vehicle.register()

        # ------------------------------------------
        # Trusted Authority Registration
        # ------------------------------------------

        status = self.ta.register_vehicle(vehicle)

        if not status:

            print("Vehicle Registration Failed")

            return False

        end = time.perf_counter()

        elapsed = (end - start) * 1000

        self.registration_times.append(elapsed)

        self.total_registered += 1

        print(f"Registration Completed : {elapsed:.3f} ms")

        return True


    # =====================================================
    # Register RSU
    # =====================================================

    def register_rsu(
        self,
        rsu: RSU
    ):

        print("\n" + "=" * 70)
        print("RSU REGISTRATION PROTOCOL")
        print("=" * 70)

        start = time.perf_counter()

        rsu.register()

        status = self.ta.register_rsu(rsu)

        if not status:

            print("RSU Registration Failed")

            return False

        end = time.perf_counter()

        elapsed = (end - start) * 1000

        print(f"Registration Completed : {elapsed:.3f} ms")

        return True
            # =====================================================
    # Register Multiple Vehicles
    # =====================================================

    def register_multiple_vehicles(
        self,
        vehicles
    ):
        """
        Register multiple vehicles with the Trusted Authority.
        """

        print("\n" + "=" * 70)
        print("BULK VEHICLE REGISTRATION")
        print("=" * 70)

        successful = 0

        failed = 0

        start = time.perf_counter()

        for vehicle in vehicles:

            status = self.register_vehicle(vehicle)

            if status:

                successful += 1

            else:

                failed += 1

        total_time = (

            time.perf_counter() - start

        ) * 1000

        print("\n" + "=" * 70)

        print("REGISTRATION SUMMARY")

        print("=" * 70)

        print(f"Successful : {successful}")

        print(f"Failed     : {failed}")

        print(f"Total Time : {total_time:.3f} ms")

        return successful


    # =====================================================
    # Register Multiple RSUs
    # =====================================================

    def register_multiple_rsus(
        self,
        rsus
    ):
        """
        Register multiple RSUs.
        """

        print("\n" + "=" * 70)
        print("BULK RSU REGISTRATION")
        print("=" * 70)

        successful = 0

        start = time.perf_counter()

        for rsu in rsus:

            if self.register_rsu(rsu):

                successful += 1

        total_time = (

            time.perf_counter() - start

        ) * 1000

        print("\n" + "=" * 70)

        print("RSU REGISTRATION SUMMARY")

        print("=" * 70)

        print(f"Registered RSUs : {successful}")

        print(f"Total Time      : {total_time:.3f} ms")

        return successful
            # =====================================================
    # Average Registration Time
    # =====================================================

    def average_registration_time(self):
        """
        Return the average registration time in milliseconds.
        """

        if not self.registration_times:

            return 0.0

        return sum(self.registration_times) / len(
            self.registration_times
        )

    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.registration_times.clear()

        self.total_registered = 0

        print("Registration Statistics Reset")

    # =====================================================
    # Registration Information
    # =====================================================

    def show_information(self):

        print("\n" + "=" * 70)
        print("VEHICLE REGISTRATION PROTOCOL")
        print("=" * 70)

        print(
            f"Registered Vehicles : {self.total_registered}"
        )

        print(
            f"Registration Records : {len(self.registration_times)}"
        )

        print(
            f"Average Time : "
            f"{self.average_registration_time():.3f} ms"
        )

        print("=" * 70)

    # =====================================================
    # Export Registration Statistics
    # =====================================================

    def get_statistics(self):

        return {

            "registered_vehicles":
                self.total_registered,

            "registration_records":
                len(self.registration_times),

            "average_registration_time":
                self.average_registration_time(),

            "registration_times":
                self.registration_times.copy()

        }

    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"VehicleRegistration("

            f"Registered={self.total_registered}, "

            f"AverageTime={self.average_registration_time():.3f} ms)"

        )