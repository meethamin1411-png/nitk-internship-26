"""
=========================================================
PQC-VANET Vehicle Model
---------------------------------------------------------
Represents a smart vehicle participating in the
Post-Quantum Certificateless VANET.

Author : Meeth Amin
=========================================================
"""

from crypto import qrng
from crypto import kyber
from crypto import dilithium

from common.models import VehicleContext
from common.protocol_types import (
    RoadType,
    PrivacyMode,
    RotationReason,
)

from context_manager import ContextManager
from threat_evaluation import ThreatEvaluation
from privacy_policy import PrivacyPolicy
from multilevel_pseudonym import MultiLevelPseudonymGenerator
from pseudonym_manager import PseudonymManager


class Vehicle:

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(

        self,

        real_id,

        trusted_authority

    ):

        self.real_id = real_id

        self.ta = trusted_authority

        # ==================================================
        # Vehicle Status
        # ==================================================

        self.status = "ACTIVE"

        self.registration_status = False

        self.revoked = False

        # ==================================================
        # Registration
        # ==================================================

        self.registration_time = None

        self.registration_token = None

        # ==================================================
        # Certificateless Identity
        # ==================================================

        self.secret_value = None

        self.partial_private_key = None

        self.partial_public_key = None
        self.partial_key_signature = None

        self.full_private_key = None

        # ==================================================
        # ML-DSA (Dilithium)
        # ==================================================

        self.sig_pk = None

        self.sig_sk = None

        # ==================================================
        # ML-KEM (Kyber)
        # ==================================================

        self.kem_pk = None

        self.kem_sk = None

        # ==================================================
        # Pseudonym
        # ==================================================

        self.current_pseudonym = None

        self.previous_pseudonym = None

        self.pseudonym_history = []
        self.pseudonym_count = 0
    # ==================================================
# Adaptive Privacy System
# ==================================================

        self.context_manager = None

        self.threat_engine = ThreatEvaluation()

        self.current_threat = None

        self.current_privacy_mode = PrivacyMode.NORMAL

        self.pseudonym_generator = MultiLevelPseudonymGenerator()

        self.pseudonym_manager = PseudonymManager()

        # ==================================================
        # Session Keys
        # ==================================================

        self.session_keys = {}

        # ==================================================
        # City Simulation
        # ==================================================

        self.position = (0, 0)

        self.speed = 0

        self.direction = 0

        self.connected_rsu = None

        # ==================================================
        # Statistics
        # ==================================================

        self.authentication_count = 0

        self.messages_sent = 0

        self.messages_received = 0

        print(f"Vehicle Created : {self.real_id}")
            # =====================================================
    # Vehicle Registration
    # =====================================================

    def register(self):

        """
        Register the vehicle with the Trusted Authority.
        """

        print("\n" + "=" * 70)
        print("REGISTERING :", self.real_id)
        print("=" * 70)

        start = time.perf_counter()

        self.registration_time = int(time.time() * 1000)

        self.registration_status = True

        end = time.perf_counter()

        print("Registration Successful")

        print(
            f"Registration Time : {(end-start)*1000:.3f} ms"
        )

        return True

    # =====================================================
    # Generate Complete Cryptographic Identity
    # =====================================================

    def initialize_crypto(self):

        """
        Generate all post-quantum cryptographic keys.
        """

        print("\nGenerating Vehicle Cryptographic Identity...")

        # -----------------------------
        # ML-DSA
        # -----------------------------

        self.sig_pk, self.sig_sk = (
            dilithium.generate_keypair()
        )

        print("✓ Dilithium Keys Generated")

        # -----------------------------
        # ML-KEM
        # -----------------------------

        self.kem_pk, self.kem_sk = (
            kyber.generate_keypair()
        )

        print("✓ Kyber Keys Generated")

        return True

    # =====================================================
    # Vehicle Secret
    # =====================================================

    def generate_secret_value(self):

        """
        Generate QRNG based secret value.
        """

        self.secret_value = (
            qrng.generate_secret_value()
        )

        print("✓ Vehicle Secret Generated")

        return self.secret_value
            # =====================================================
    # Digital Signature (ML-DSA)
    # =====================================================

    def sign_message(self, message):
        """
        Sign a message using Dilithium.
        """

        if isinstance(message, str):
            message = message.encode()

        signature = dilithium.sign_message(
            self.sig_sk,
            message
        )

        self.messages_sent += 1

        return signature

    # =====================================================
    # Verify Peer Signature
    # =====================================================

    def verify_peer_signature(
        self,
        public_key,
        message,
        signature
    ):
        """
        Verify a received Dilithium signature.
        """

        if isinstance(message, str):
            message = message.encode()

        status = dilithium.verify_signature(
            public_key,
            message,
            signature
        )

        if status:
            self.messages_received += 1

        return status

    # =====================================================
    # Generate New ML-KEM Key Pair
    # =====================================================

    def refresh_kem_keys(self):
        """
        Generate a fresh Kyber key pair.
        """

        self.kem_pk, self.kem_sk = (
            kyber.generate_keypair()
        )

        print("✓ New Kyber Key Pair Generated")

        return self.kem_pk

    # =====================================================
    # Derive Session Key
    # =====================================================

    def derive_session_key(
        self,
        shared_secret,
        context
    ):
        """
        Derive a secure session key from the shared secret.
        """

        session_key = kyber.derive_session_key(
            shared_secret,
            context
        )

        self.session_keys[context] = session_key

        return session_key

    # =====================================================
    # Get Existing Session Key
    # =====================================================

    def get_session_key(
        self,
        context
    ):

        return self.session_keys.get(context, None)
            # =====================================================
    # Generate Dynamic Pseudonym
    # =====================================================

    def generate_pseudonym(self):
        """
        Generate a new dynamic pseudonym for the vehicle.
        """

        timestamp = int(time.time() * 1000)

        random_seed = qrng.generate_random_hex(16)

        pseudonym = hashlib.sha3_256(

            (
                self.real_id +
                random_seed +
                str(timestamp)
            ).encode()

        ).hexdigest()[:24]

        self.previous_pseudonym = self.current_pseudonym

        self.current_pseudonym = pseudonym

        trace_record = hashlib.sha3_256(

            (
                self.real_id +
                str(timestamp)
            ).encode()

        ).hexdigest()

        record = {

            "pseudonym": pseudonym,

            "timestamp": timestamp,

            "trace_record": trace_record

        }

        self.pseudonym_history.append(record)

        if self.ta is not None:

            self.ta.update_pseudonym(

                self.real_id,

                pseudonym

            )

        print(f"✓ New Pseudonym Generated : {pseudonym}")

        return pseudonym

    # =====================================================
    # Initialize Adaptive Context
    # =====================================================

    def initialize_context(
        self,
        road_id,
        road_type,
        traffic_density,
        vehicle_speed,
        security_alert,
        rsu_trust_score,
        emergency_mode=False
    ):
        """
        Initialize adaptive vehicle context.
        """

        context = VehicleContext(

            vehicle_id=self.real_id,

            road_id=road_id,

            road_type=road_type,

            traffic_density=traffic_density,

            vehicle_speed=vehicle_speed,

            security_alert=security_alert,

            rsu_trust_score=rsu_trust_score,

            emergency_mode=emergency_mode,

            privacy_mode=self.current_privacy_mode,

            timestamp=datetime.now()

        )

        self.context_manager = ContextManager(context)

        return context

    # =====================================================
    # Update Adaptive Pseudonym
    # =====================================================

    def update_adaptive_pseudonym(self):
        """
        Generate a context-aware adaptive pseudonym.
        """

        if self.context_manager is None:

            raise ValueError(
                "Vehicle context has not been initialized."
            )

        # ---------------------------------------------
        # Current Context
        # ---------------------------------------------

        context = self.context_manager.get_context()

        # ---------------------------------------------
        # Threat Evaluation
        # ---------------------------------------------

        self.current_threat = self.threat_engine.evaluate(
            context
        )

        # ---------------------------------------------
        # Privacy Policy
        # ---------------------------------------------

        self.current_privacy_mode = (
            PrivacyPolicy.select_privacy_mode(
                self.current_threat.level
            )
        )

        # ---------------------------------------------
        # Update Context
        # ---------------------------------------------

        self.context_manager.update_context(

            privacy_mode=self.current_privacy_mode

        )

        # ---------------------------------------------
        # Generate Adaptive Pseudonym
        # ---------------------------------------------

        pseudonym = self.pseudonym_generator.generate_pseudonym(

            vehicle_id=self.real_id,

            road_id=context.road_id,

            threat_level=self.current_threat.level.value,

            privacy_mode=self.current_privacy_mode

        )

        # ---------------------------------------------
        # Store using Pseudonym Manager
        # ---------------------------------------------

        self.pseudonym_manager.store_pseudonym(

            pid=pseudonym.pid,

            privacy_mode=self.current_privacy_mode,

            rotation_reason=RotationReason.CONTEXT_CHANGE

        )

        # ---------------------------------------------
        # Update Vehicle Identity
        # ---------------------------------------------

        self.previous_pseudonym = self.current_pseudonym

        self.current_pseudonym = pseudonym.pid

        self.pseudonym_history.append(

            {

                "pid": pseudonym.pid,

                "privacy_mode": self.current_privacy_mode.value,

                "threat": self.current_threat.level.value,

                "timestamp": context.timestamp

            }

        )

        print()

        print("✓ Adaptive Pseudonym Updated")

        print(f"Threat Level : {self.current_threat.level.value}")

        print(f"Privacy Mode : {self.current_privacy_mode.value}")

        print(f"Current PID  : {self.current_pseudonym}")

        return pseudonym


    # =====================================================
    # Get Current Pseudonym
    # =====================================================

    def get_current_pseudonym(self):

        return self.current_pseudonym


    # =====================================================
    # Get Previous Pseudonym
    # =====================================================

    def get_previous_pseudonym(self):

        return self.previous_pseudonym


    # =====================================================
    # Display Pseudonym History
    # =====================================================

    def show_pseudonym_history(self):

        print("\n" + "=" * 60)

        print("PSEUDONYM HISTORY")

        print("=" * 60)

        for index, record in enumerate(

            self.pseudonym_history,

            start=1

        ):

            print(f"{index}. {record['pseudonym']}")

        print("=" * 60)


    # =====================================================
    # Trace Record
    # =====================================================

    def get_trace_record(self):

        if not self.pseudonym_history:

            return None

        return self.pseudonym_history[-1]["trace_record"]
            # =====================================================
    # Connect to RSU
    # =====================================================

    def connect_to_rsu(self, rsu):

        self.connected_rsu = rsu

        print(f"{self.real_id} connected to {rsu.rsu_id}")

        return True

    # =====================================================
    # Disconnect from RSU
    # =====================================================

    def disconnect_from_rsu(self):

        if self.connected_rsu is not None:

            print(
                f"{self.real_id} disconnected from "
                f"{self.connected_rsu.rsu_id}"
            )

        self.connected_rsu = None

    # =====================================================
    # Update Vehicle Position
    # =====================================================

    def update_position(
        self,
        x,
        y,
        speed=0,
        direction=0
    ):

        self.position = (x, y)

        self.speed = speed

        self.direction = direction

    # =====================================================
    # Reset Session Keys
    # =====================================================

    def reset_session_keys(self):

        self.session_keys.clear()

        print("✓ Session Keys Cleared")

    # =====================================================
    # Vehicle Information
    # =====================================================

    def show_information(self):

        print("\n" + "=" * 70)
        print("VEHICLE INFORMATION")
        print("=" * 70)

        print(f"Vehicle ID             : {self.real_id}")

        print(f"Status                 : {self.status}")

        print(f"Registration           : {self.registration_status}")

        print(f"Registration Time      : {self.registration_time}")

        print(f"Current Pseudonym      : {self.current_pseudonym}")

        print(f"Previous Pseudonym     : {self.previous_pseudonym}")

        print(f"Pseudonym Count        : {len(self.pseudonym_history)}")

        print(f"Connected RSU          : "
              f"{self.connected_rsu.rsu_id if self.connected_rsu else 'None'}")

        print(f"Vehicle Position       : {self.position}")

        print(f"Vehicle Speed          : {self.speed} km/h")

        print(f"Direction              : {self.direction}")

        print(f"Authentication Count   : {self.authentication_count}")

        print(f"Messages Sent          : {self.messages_sent}")

        print(f"Messages Received      : {self.messages_received}")

        print(f"Stored Session Keys    : {len(self.session_keys)}")

        print("=" * 70)

       # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (
            f"Vehicle("
            f"ID={self.real_id}, "
            f"Pseudonym={self.current_pseudonym}, "
            f"Status={self.status})"
        )


