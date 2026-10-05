"""
=========================================================
Trusted Authority
---------------------------------------------------------
Central authority for the PQC-VANET.

Responsibilities
----------------
• Vehicle Registration
• RSU Registration
• Certificateless Key Generation
• Traceability
• Revocation
• Public Key Management

Author : Meeth Amin
=========================================================
"""

import hashlib
import time

from crypto import qrng
from crypto import dilithium


class TrustedAuthority:

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(self):

        print("\n" + "=" * 70)
        print("INITIALIZING TRUSTED AUTHORITY")
        print("=" * 70)

        # ==================================================
        # Master Keys
        # ==================================================

        self.master_secret_key = qrng.generate_random_bytes(32)

        self.master_public_key = hashlib.sha3_256(
            self.master_secret_key
        ).digest()

        # ==================================================
        # Trusted Authority ML-DSA Keys
        # ==================================================

        self.ta_pk, self.ta_sk = (
            dilithium.generate_keypair()
        )

        # ==================================================
        # Registries
        # ==================================================

        self.vehicle_registry = {}

        self.rsu_registry = {}

        self.revocation_list = set()

        # ==================================================
        # Counters
        # ==================================================

        self.total_registered_vehicles = 0

        self.total_registered_rsus = 0

        # ==================================================
        # Statistics
        # ==================================================

        self.registration_times = []

        self.authentication_logs = []

        self.traceability_logs = []

        print("✓ Master Secret Key Generated")

        print("✓ Master Public Key Generated")

        print("✓ Trusted Authority Ready")
            # =====================================================
    # Generate Vehicle Identification Number (VIN)
    # =====================================================

    def generate_vin(self):

        self.total_registered_vehicles += 1

        return f"VIN{self.total_registered_vehicles:06d}"


    # =====================================================
    # Generate Registration Token
    # =====================================================

    def generate_registration_token(self):

        return qrng.generate_random_hex(16)


    # =====================================================
    # Register Vehicle
    # =====================================================

    def register_vehicle(self, vehicle):

        print("\n" + "=" * 70)
        print("VEHICLE REGISTRATION")
        print("=" * 70)

        start = time.perf_counter()

        # Already Registered
        if vehicle.real_id in self.vehicle_registry:

            print("Vehicle Already Registered")

            return False

        vin = self.generate_vin()

        token = self.generate_registration_token()

        vehicle.registration_status = True

        vehicle.registration_time = int(
            time.time() * 1000
        )

        vehicle.registration_token = token

        vehicle.vin = vin

        self.vehicle_registry[vehicle.real_id] = {

            "vin": vin,

            "vehicle": vehicle,

            "status": "ACTIVE",

            "registration_token": token,

            "registration_time":
                vehicle.registration_time,

            "current_pseudonym": None,

            "revoked": False
        }

        elapsed = (

            time.perf_counter() - start

        ) * 1000

        self.registration_times.append(elapsed)

        print(f"Vehicle ID : {vehicle.real_id}")

        print(f"VIN        : {vin}")

        print("Registration Successful")

        print(f"Time : {elapsed:.3f} ms")

        return True


    # =====================================================
    # Register RSU
    # =====================================================

    def register_rsu(self, rsu):

        print("\nRegistering RSU...")

        if rsu.rsu_id in self.rsu_registry:

            print("RSU Already Registered")

            return False

        self.total_registered_rsus += 1

        self.rsu_registry[rsu.rsu_id] = {

            "rsu": rsu,

            "status": "ACTIVE",

            "registration_time":
                int(time.time() * 1000)
        }

        print(f"RSU Registered : {rsu.rsu_id}")

        return True
            # =====================================================
    # Generate Partial Private Key
    # =====================================================

    def generate_partial_private_key(self, vehicle):

        digest = hashlib.sha3_256()

        digest.update(self.master_secret_key)

        digest.update(vehicle.real_id.encode())

        digest.update(vehicle.secret_value)

        partial_private_key = digest.digest()

        return partial_private_key


    # =====================================================
    # Generate Partial Public Key
    # =====================================================

    def generate_partial_public_key(
        self,
        partial_private_key
    ):

        return hashlib.sha3_256(
            partial_private_key
        ).digest()


    # =====================================================
    # Issue Certificateless Keys
    # =====================================================

    def issue_partial_keys(self, vehicle):

        print("\nIssuing Certificateless Keys...")

        # ----------------------------------------------
        # Vehicle Secret
        # ----------------------------------------------

        if vehicle.secret_value is None:

            vehicle.generate_secret_value()

        # ----------------------------------------------
        # Partial Keys
        # ----------------------------------------------

        vehicle.partial_private_key = (

            self.generate_partial_private_key(
                vehicle
            )

        )

        vehicle.partial_public_key = (

            self.generate_partial_public_key(

                vehicle.partial_private_key

            )

        )

        # ----------------------------------------------
        # TA Signature
        # ----------------------------------------------

        vehicle.partial_key_signature = (

            dilithium.sign_message(

                self.ta_sk,

                vehicle.partial_public_key

            )

        )

        print("✓ Partial Private Key Generated")

        print("✓ Partial Public Key Generated")

        print("✓ TA Signature Generated")

        return True


    # =====================================================
    # Store Vehicle Cryptographic Information
    # =====================================================

    def store_vehicle_keys(self, vehicle):

        if vehicle.real_id not in self.vehicle_registry:

            return False

        self.vehicle_registry[vehicle.real_id].update({

            "partial_public_key":
                vehicle.partial_public_key,

            "signature_public_key":
                vehicle.sig_pk,

            "kem_public_key":
                vehicle.kem_pk,

            "partial_key_signature":
                vehicle.partial_key_signature

        })

        print("✓ Vehicle Keys Stored")

        return True
            # =====================================================
    # Public Key Lookup
    # =====================================================

    def get_signature_public_key(self, vehicle_id):

        record = self.vehicle_registry.get(vehicle_id)

        if record is None:
            return None

        return record.get("signature_public_key")


    def get_kem_public_key(self, vehicle_id):

        record = self.vehicle_registry.get(vehicle_id)

        if record is None:
            return None

        return record.get("kem_public_key")


    # =====================================================
    # Update Vehicle Pseudonym
    # =====================================================

    def update_pseudonym(
        self,
        vehicle_id,
        pseudonym
    ):

        if vehicle_id not in self.vehicle_registry:

            return False

        vehicle = self.vehicle_registry[vehicle_id]["vehicle"]

        vehicle.current_pseudonym = pseudonym
        self.vehicle_registry[vehicle_id][
            "current_pseudonym"
        ] = pseudonym

        history = self.vehicle_registry[vehicle_id].setdefault(
            "pseudonym_history",
            []
        )

        history.append(pseudonym)

        return True


    # =====================================================
    # Trace Vehicle
    # =====================================================

    def trace_vehicle(
        self,
        pseudonym
    ):

        start = time.perf_counter()

        for vehicle_id, record in self.vehicle_registry.items():

            if record.get("current_pseudonym") == pseudonym:

                elapsed = (
                    time.perf_counter() - start
                ) * 1000

                self.traceability_logs.append(elapsed)

                return vehicle_id

            if pseudonym in record.get(
                "pseudonym_history",
                []
            ):

                elapsed = (
                    time.perf_counter() - start
                ) * 1000

                self.traceability_logs.append(elapsed)

                return vehicle_id

        return None


    # =====================================================
    # Revoke Vehicle
    # =====================================================

    def revoke_vehicle(
        self,
        vehicle_id
    ):

        if vehicle_id not in self.vehicle_registry:

            return False

        self.vehicle_registry[vehicle_id][
            "status"
        ] = "REVOKED"

        self.vehicle_registry[vehicle_id][
            "revoked"
        ] = True

        self.revocation_list.add(vehicle_id)

        print(f"Vehicle Revoked : {vehicle_id}")

        return True


    # =====================================================
    # Revocation Check
    # =====================================================

    def is_revoked(
        self,
        vehicle_id
    ):

        return vehicle_id in self.revocation_list


    # =====================================================
    # Vehicle Status
    # =====================================================

    def get_vehicle_status(
        self,
        vehicle_id
    ):

        if vehicle_id not in self.vehicle_registry:

            return "UNKNOWN"

        return self.vehicle_registry[
            vehicle_id
        ]["status"]
            # =====================================================
    # Check Registration
    # =====================================================

    def is_registered(self, vehicle_id):

        return vehicle_id in self.vehicle_registry

    # =====================================================
    # Get Vehicle Information
    # =====================================================

    def get_vehicle_information(self, vehicle_id):

        return self.vehicle_registry.get(vehicle_id, None)

    # =====================================================
    # Authentication Log
    # =====================================================

    def log_authentication(
        self,
        vehicle_id,
        status,
        timestamp=None
    ):

        if timestamp is None:

            timestamp = int(time.time() * 1000)

        self.authentication_logs.append({

            "vehicle_id": vehicle_id,

            "status": status,

            "timestamp": timestamp

        })

    # =====================================================
    # Display Vehicle Registry
    # =====================================================

    def show_vehicle_registry(self):

        print("\n" + "=" * 70)
        print("VEHICLE REGISTRY")
        print("=" * 70)

        if not self.vehicle_registry:

            print("No Registered Vehicles")

            print("=" * 70)

            return

        for vehicle_id, record in self.vehicle_registry.items():

            print(f"\nVehicle ID        : {vehicle_id}")

            print(f"VIN               : {record['vin']}")

            print(f"Status            : {record['status']}")

            print(f"Revoked           : {record['revoked']}")

            print(f"Registration Time : {record['registration_time']}")

            print(f"Pseudonym         : {record['current_pseudonym']}")

        print("\n" + "=" * 70)

    # =====================================================
    # Display RSU Registry
    # =====================================================

    def show_rsu_registry(self):

        print("\n" + "=" * 70)
        print("RSU REGISTRY")
        print("=" * 70)

        if not self.rsu_registry:

            print("No Registered RSUs")

            print("=" * 70)

            return

        for rsu_id, record in self.rsu_registry.items():

            print(f"\nRSU ID            : {rsu_id}")

            print(f"Status            : {record['status']}")

            print(f"Registration Time : {record['registration_time']}")

        print("\n" + "=" * 70)

    # =====================================================
    # Trusted Authority Information
    # =====================================================

    def show_information(self):

        print("\n" + "=" * 70)
        print("TRUSTED AUTHORITY INFORMATION")
        print("=" * 70)

        print(f"Registered Vehicles : {len(self.vehicle_registry)}")

        print(f"Registered RSUs     : {len(self.rsu_registry)}")

        print(f"Revoked Vehicles    : {len(self.revocation_list)}")

        print(f"Authentication Logs : {len(self.authentication_logs)}")

        print(f"Traceability Logs   : {len(self.traceability_logs)}")

        print("=" * 70)
            # =====================================================
    # Get Vehicle By Current Pseudonym
    # =====================================================

    def get_vehicle_by_pseudonym(
        self,
        pseudonym
    ):
        """
        Return the vehicle object corresponding to
        the supplied pseudonym.
        """

        for record in self.vehicle_registry.values():

            vehicle = record["vehicle"]

            if vehicle.current_pseudonym == pseudonym:

                return vehicle

        return None


    # =====================================================
    # Get Vehicle Public Keys
    # =====================================================

    def get_vehicle_public_keys(
        self,
        vehicle_id
    ):

        record = self.vehicle_registry.get(vehicle_id)

        if record is None:

            return None

        vehicle = record["vehicle"]

        return {

            "signature_public_key":
                vehicle.sig_pk,

            "kem_public_key":
                vehicle.kem_pk,

            "partial_public_key":
                vehicle.partial_public_key

        }


    # =====================================================
    # Get Vehicle Partial Keys
    # =====================================================

    def get_vehicle_partial_keys(
        self,
        vehicle_id
    ):

        record = self.vehicle_registry.get(vehicle_id)

        if record is None:

            return None

        vehicle = record["vehicle"]

        return {

            "partial_private_key":
                vehicle.partial_private_key,

            "partial_public_key":
                vehicle.partial_public_key,

            "ta_signature":
                vehicle.partial_key_signature

        }


    # =====================================================
    # Get Vehicle Object
    # =====================================================

    def get_vehicle(
        self,
        vehicle_id
    ):

        record = self.vehicle_registry.get(vehicle_id)

        if record is None:

            return None

        return record["vehicle"]


    # =====================================================
    # Get Registration Record
    # =====================================================

    def get_registration_record(
        self,
        vehicle_id
    ):

        return self.vehicle_registry.get(
            vehicle_id,
            None
        )

    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"TrustedAuthority("

            f"Vehicles={len(self.vehicle_registry)}, "

            f"RSUs={len(self.rsu_registry)})"

        )