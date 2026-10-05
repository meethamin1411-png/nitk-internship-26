"""
=========================================================
Road Side Unit (RSU)
---------------------------------------------------------
Represents a trusted Road Side Unit in the PQC-VANET.

Responsibilities
----------------
• Vehicle Authentication
• V2I Communication
• Session Key Management
• Safety Message Broadcasting
• Traffic Monitoring

Author : Meeth Amin
=========================================================
"""

import time

from crypto import kyber
from crypto import dilithium


class RSU:

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(

        self,

        rsu_id,

        trusted_authority

    ):

        self.rsu_id = rsu_id

        self.ta = trusted_authority

        # ==================================================
        # Status
        # ==================================================

        self.status = "ACTIVE"

        self.registration_status = False

        self.registration_time = None

        # ==================================================
        # Dilithium Keys
        # ==================================================

        self.sig_pk = None

        self.sig_sk = None

        # ==================================================
        # Kyber Keys
        # ==================================================

        self.kem_pk = None

        self.kem_sk = None

        # ==================================================
        # Connected Vehicles
        # ==================================================

        self.connected_vehicles = {}

        # ==================================================
        # Session Keys
        # ==================================================

        self.session_keys = {}

        # ==================================================
        # City Simulation
        # ==================================================

        self.position = (0, 0)

        self.coverage_radius = 300

        # ==================================================
        # Statistics
        # ==================================================

        self.messages_sent = 0

        self.messages_received = 0

        self.authentication_count = 0

        print(f"RSU Created : {self.rsu_id}")
            # =====================================================
    # Register RSU
    # =====================================================

    def register(self):
        """
        Register the RSU with the Trusted Authority.
        """

        print("\n" + "=" * 70)
        print(f"REGISTERING RSU : {self.rsu_id}")
        print("=" * 70)

        start = time.perf_counter()

        self.registration_status = True

        self.registration_time = int(
            time.time() * 1000
        )

        end = time.perf_counter()

        print("RSU Registration Successful")

        print(
            f"Registration Time : {(end-start)*1000:.3f} ms"
        )

        return True


    # =====================================================
    # Initialize Cryptographic Keys
    # =====================================================

    def initialize_crypto(self):

        print("\nGenerating RSU Cryptographic Identity...")

        # -----------------------------
        # ML-DSA (Dilithium)
        # -----------------------------

        self.sig_pk, self.sig_sk = (

            dilithium.generate_keypair()

        )

        print("✓ Dilithium Keys Generated")

        # -----------------------------
        # ML-KEM (Kyber)
        # -----------------------------

        self.kem_pk, self.kem_sk = (

            kyber.generate_keypair()

        )

        print("✓ Kyber Keys Generated")

        return True


    # =====================================================
    # Refresh Kyber Keys
    # =====================================================

    def refresh_kem_keys(self):

        self.kem_pk, self.kem_sk = (

            kyber.generate_keypair()

        )

        print("✓ RSU Kyber Keys Refreshed")

        return self.kem_pk


    # =====================================================
    # Derive Session Key
    # =====================================================

    def derive_session_key(

        self,

        shared_secret,

        context

    ):

        session_key = kyber.derive_session_key(

            shared_secret,

            context

        )

        self.session_keys[context] = session_key

        return session_key


    # =====================================================
    # Get Session Key
    # =====================================================

    def get_session_key(

        self,

        context

    ):

        return self.session_keys.get(

            context,

            None

        )
            # =====================================================
    # Authenticate Vehicle
    # =====================================================

    def authenticate_vehicle(self, vehicle):
        """
        Authenticate a vehicle before allowing V2I
        communication.
        """

        print("\nAuthenticating Vehicle...")

        # -----------------------------------------
        # Registration Check
        # -----------------------------------------

        if not self.ta.is_registered(vehicle.real_id):

            print("✗ Vehicle Not Registered")

            return False

        # -----------------------------------------
        # Revocation Check
        # -----------------------------------------

        if self.ta.is_revoked(vehicle.real_id):

            print("✗ Vehicle Revoked")

            return False

        # -----------------------------------------
        # Authentication Success
        # -----------------------------------------

        self.authentication_count += 1

        self.ta.log_authentication(

            vehicle.real_id,

            "SUCCESS"

        )

        print("✓ Authentication Successful")

        return True


    # =====================================================
    # Connect Vehicle
    # =====================================================

    def connect_vehicle(self, vehicle):

        if not self.authenticate_vehicle(vehicle):

            return False

        self.connected_vehicles[

            vehicle.real_id

        ] = vehicle

        vehicle.connected_rsu = self

        print(

            f"{vehicle.real_id} connected "

            f"to {self.rsu_id}"

        )

        return True


    # =====================================================
    # Disconnect Vehicle
    # =====================================================

    def disconnect_vehicle(self, vehicle):

        if vehicle.real_id in self.connected_vehicles:

            del self.connected_vehicles[

                vehicle.real_id

            ]

        vehicle.connected_rsu = None

        print(

            f"{vehicle.real_id} disconnected "

            f"from {self.rsu_id}"

        )


    # =====================================================
    # Check Connection
    # =====================================================

    def is_connected(self, vehicle_id):

        return vehicle_id in self.connected_vehicles


    # =====================================================
    # Get Connected Vehicle
    # =====================================================

    def get_vehicle(self, vehicle_id):

        return self.connected_vehicles.get(

            vehicle_id,

            None

        )
            # =====================================================
    # Receive Message from Vehicle
    # =====================================================

    def receive_message(
        self,
        vehicle,
        message
    ):

        print("\n" + "=" * 60)
        print("V2I MESSAGE RECEIVED")
        print("=" * 60)

        if not self.is_connected(vehicle.real_id):

            print("Vehicle Not Connected")

            return False

        self.messages_received += 1

        print(f"Vehicle : {vehicle.real_id}")

        print(f"Message : {message}")

        return True


    # =====================================================
    # Send Message to Vehicle
    # =====================================================

    def send_message(
        self,
        vehicle,
        message
    ):

        if not self.is_connected(vehicle.real_id):

            print("Vehicle Not Connected")

            return False

        self.messages_sent += 1

        print("\n" + "=" * 60)
        print("RSU RESPONSE")
        print("=" * 60)

        print(f"RSU : {self.rsu_id}")

        print(f"Vehicle : {vehicle.real_id}")

        print(f"Message : {message}")

        return True


    # =====================================================
    # Broadcast Safety Message
    # =====================================================

    def broadcast_message(
        self,
        message
    ):

        print("\n" + "=" * 60)
        print("SAFETY MESSAGE BROADCAST")
        print("=" * 60)

        print(f"RSU : {self.rsu_id}")

        print(f"Broadcast : {message}")

        for vehicle in self.connected_vehicles.values():

            print(

                f" -> Sent to "

                f"{vehicle.real_id}"

            )

            self.messages_sent += 1

        return True


    # =====================================================
    # Vehicle Count
    # =====================================================

    def vehicle_count(self):

        return len(

            self.connected_vehicles

        )


    # =====================================================
    # Remove All Vehicles
    # =====================================================

    def clear_connections(self):

        for vehicle in self.connected_vehicles.values():

            vehicle.connected_rsu = None

        self.connected_vehicles.clear()

        print("All Vehicles Disconnected")
            # =====================================================
    # Update RSU Position
    # =====================================================

    def update_position(
        self,
        x,
        y,
        coverage_radius=None
    ):

        self.position = (x, y)

        if coverage_radius is not None:

            self.coverage_radius = coverage_radius

    # =====================================================
    # Display Connected Vehicles
    # =====================================================

    def show_connected_vehicles(self):

        print("\n" + "=" * 70)
        print("CONNECTED VEHICLES")
        print("=" * 70)

        if not self.connected_vehicles:

            print("No Connected Vehicles")

        else:

            for vehicle in self.connected_vehicles.values():

                print(

                    f"{vehicle.real_id}"

                    f"  ->  "

                    f"{vehicle.current_pseudonym}"

                )

        print("=" * 70)

    # =====================================================
    # RSU Information
    # =====================================================

    def show_information(self):

        print("\n" + "=" * 70)
        print("ROAD SIDE UNIT INFORMATION")
        print("=" * 70)

        print(f"RSU ID                 : {self.rsu_id}")

        print(f"Status                 : {self.status}")

        print(f"Registration Status    : {self.registration_status}")

        print(f"Registration Time      : {self.registration_time}")

        print(f"Position               : {self.position}")

        print(f"Coverage Radius        : {self.coverage_radius} m")

        print(f"Connected Vehicles     : {len(self.connected_vehicles)}")

        print(f"Authentication Count   : {self.authentication_count}")

        print(f"Messages Sent          : {self.messages_sent}")

        print(f"Messages Received      : {self.messages_received}")

        print(f"Stored Session Keys    : {len(self.session_keys)}")

        print("=" * 70)

    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.messages_sent = 0

        self.messages_received = 0

        self.authentication_count = 0

        print("RSU Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"RSU("

            f"ID={self.rsu_id}, "

            f"Vehicles={len(self.connected_vehicles)}, "

            f"Status={self.status})"

        )