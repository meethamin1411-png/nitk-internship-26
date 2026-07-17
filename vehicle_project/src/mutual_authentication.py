"""
=========================================================
Mutual Authentication Protocol
---------------------------------------------------------
Provides post-quantum mutual authentication between

• Vehicle ↔ Vehicle
• Vehicle ↔ RSU

using

• Certificateless Cryptography
• ML-DSA (Dilithium)
• ML-KEM (Kyber)
• QRNG Nonces
• Authentication Confidence Token (ACT)

Author : Meeth Amin
=========================================================
"""

import time

from crypto import qrng
from crypto import dilithium
from crypto import kyber
from crypto import hash_utils

from models import Vehicle
from models import RSU
from models import TrustedAuthority
from context_aware_session_key import ContextAwareSessionKey


class MutualAuthentication:
    """
    PQC Mutual Authentication Manager
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        trusted_authority: TrustedAuthority
    ):

        self.ta = trusted_authority

        # =================================================
        # Active Sessions
        # =================================================

        self.active_sessions = {}

        # =================================================
        # Replay Protection
        # =================================================

        self.used_nonces = set()

        self.used_timestamps = set()

        # =================================================
        # Authentication Logs
        # =================================================

        self.authentication_logs = []

        self.authentication_times = []

        # =================================================
        # Statistics
        # =================================================

        self.successful_authentications = 0

        self.failed_authentications = 0

        # =================================================
        # Session Configuration
        # =================================================

        self.session_timeout = 300

        self.timestamp_window = 30

        print(
            "\nMutual Authentication Protocol Initialized"
        )
        self.context_key_manager = ContextAwareSessionKey()

    # =====================================================
    # Create Authentication Request (Message M1)
    # =====================================================

    def create_auth_request(
        self,
        sender,
        receiver
    ):
        """
        Create the first authentication request.
        """

        print("\nCreating Authentication Request...")

        print("Generating Authentication Confidence Token...")

        # -------------------------------------------------
        # Timestamp
        # -------------------------------------------------

        timestamp = int(time.time())

        # -------------------------------------------------
        # QRNG Nonce
        # -------------------------------------------------

        nonce = qrng.generate_random_bytes(16)

        # -------------------------------------------------
        # Authentication Confidence Token Parameters
        # -------------------------------------------------

        road_segment = "RS-001"

        vehicle_state = "ACTIVE"

        # -------------------------------------------------
        # Generate ACT
        # -------------------------------------------------

        act = hash_utils.generate_act(

            sender.current_pseudonym,

            nonce,

            road_segment,

            vehicle_state,

            timestamp

        )
        print("ACT Generated")

        # -------------------------------------------------
        # Receiver Identity
        # -------------------------------------------------

        receiver_identity = (

            receiver.rsu_id

            if isinstance(receiver, RSU)

            else receiver.current_pseudonym

        )

        # -------------------------------------------------
        # Build Signed Message
        # -------------------------------------------------

        message = (

            str(sender.current_pseudonym)

            + str(receiver_identity)

            + str(timestamp)

            + nonce.hex()

            + road_segment

            + vehicle_state

            + act

        ).encode()

        # -------------------------------------------------
        # Generate Dilithium Signature
        # -------------------------------------------------

        signature = dilithium.sign_message(

            sender.sig_sk,

            message

        )

        # -------------------------------------------------
        # Authentication Request (M1)
        # -------------------------------------------------

        request = {

    "sender_id":
        sender.real_id,

    "sender_pseudonym":
        sender.current_pseudonym,

    "receiver":
        receiver_identity,

    "timestamp":
        timestamp,

    "nonce":
        nonce,

    # -----------------------------------
    # Authentication Confidence Token
    # -----------------------------------

    "road_segment":
        road_segment,

    "vehicle_state":
        vehicle_state,

    "act":
        act,

    # -----------------------------------
    # PQC Signature
    # -----------------------------------

    "signature":
        signature,

    # -----------------------------------
    # ML-KEM Public Key
    # -----------------------------------

    "kem_public_key":
        sender.kem_pk

}
        return request
            # =====================================================
    # Verify Authentication Request (Message M1)
    # =====================================================

    def verify_auth_request(
        self,
        receiver,
        request
    ):
        """
        Verify an incoming authentication request.
        """

        print("\nVerifying Authentication Request...")

        print(">>> ACT VERIFICATION FUNCTION EXECUTING <<<")

        # -------------------------------------------------
        # Timestamp Validation
        # -------------------------------------------------

        current_time = int(time.time())

        if abs(current_time - request["timestamp"]) > self.timestamp_window:

            print("Authentication Failed : Timestamp Expired")

            self.failed_authentications += 1

            return False

        # -------------------------------------------------
        # Replay Protection
        # -------------------------------------------------

        nonce_hex = request["nonce"].hex()

        if nonce_hex in self.used_nonces:

            print("Authentication Failed : Replay Attack")

            self.failed_authentications += 1

            return False

        self.used_nonces.add(nonce_hex)

        # -------------------------------------------------
        # Lookup Sender using Pseudonym
        # -------------------------------------------------

        sender = self.ta.get_vehicle_by_pseudonym(

            request["sender_pseudonym"]

        )

        if sender is None:

            print("Authentication Failed : Unknown Vehicle")

            self.failed_authentications += 1

            return False

        # -------------------------------------------------
        # Revocation Check
        # -------------------------------------------------

        if self.ta.is_revoked(sender.real_id):

            print("Authentication Failed : Revoked Vehicle")

            self.failed_authentications += 1

            return False


        # -------------------------------------------------
        # Authentication Confidence Token Verification
        # -------------------------------------------------

        print("Verifying Authentication Confidence Token...")

        if not hash_utils.verify_act(

            request["act"],

            request["sender_pseudonym"],

            request["nonce"],

            request["road_segment"],

            request["vehicle_state"],

            request["timestamp"]

        ):

            print("Authentication Failed : Invalid ACT")

            self.failed_authentications += 1

            return False

        print("ACT Verified")
                # =====================================================
        # Context Check
        # =====================================================

        print("Performing Context Check...")

        # ---------------------------------------------
        # Check Vehicle State
        # ---------------------------------------------

        allowed_states = [

            "ACTIVE",

            "EMERGENCY"

        ]

        if request["vehicle_state"] not in allowed_states:

            print("Authentication Failed : Invalid Vehicle State")

            self.failed_authentications += 1

            return False

        # ---------------------------------------------
        # Check Road Segment
        # ---------------------------------------------

        allowed_segments = [

            "RS-001",

            "NH66",

            "CITY_ZONE",

            "MILITARY_ZONE"

        ]

        if request["road_segment"] not in allowed_segments:

            print("Authentication Failed : Invalid Road Segment")

            self.failed_authentications += 1

            return False

        print("Context Check Passed")

        # -------------------------------------------------
        # Receiver Identity
        # -------------------------------------------------

        receiver_identity = (

            receiver.rsu_id

            if isinstance(receiver, RSU)

            else receiver.current_pseudonym

        )

        # -------------------------------------------------
        # Rebuild Signed Message
        # -------------------------------------------------

        message = (

            str(request["sender_pseudonym"])

            + str(receiver_identity)

            + str(request["timestamp"])

            + nonce_hex

            + request["road_segment"]

            + request["vehicle_state"]

            + request["act"]

        ).encode()
                # =====================================================
        # ML-DSA Verification
        # =====================================================

        print("Performing ML-DSA Signature Verification...")

        # -------------------------------------------------
        # Dilithium Signature Verification
        # -------------------------------------------------

        if not dilithium.verify_signature(

            sender.sig_pk,

            message,

            request["signature"]

        ):

            print("Authentication Failed : Invalid Signature")

            self.failed_authentications += 1

            return False
                # =====================================================
        # ML-DSA Verification
        # =====================================================

        print("Performing ML-DSA Signature Verification...")

        print("Authentication Request Verified")

        return True
                
            # =====================================================
    # Create Authentication Response (Message M2)
    # =====================================================

    def create_auth_response(
        self,
        responder,
        initiator
    ):
        """
        Create authentication response (Message M2).
        """

        print("\nCreating Authentication Response...")

        # -------------------------------------------------
        # Timestamp
        # -------------------------------------------------

        timestamp = int(time.time())

        # -------------------------------------------------
        # Generate QRNG Nonce
        # -------------------------------------------------

        nonce = qrng.generate_random_bytes(16)

        # -------------------------------------------------
        # Responder Identity
        # -------------------------------------------------

        responder_identity = (

            responder.current_pseudonym

            if isinstance(responder, Vehicle)

            else responder.rsu_id

        )

        # -------------------------------------------------
        # Build Signed Message
        # -------------------------------------------------

        message = (

            str(responder_identity)

            + str(initiator.current_pseudonym)

            + str(timestamp)

            + nonce.hex()

        ).encode()

        # -------------------------------------------------
        # Generate Dilithium Signature
        # -------------------------------------------------

        signature = dilithium.sign_message(

            responder.sig_sk,

            message

        )

        # -------------------------------------------------
        # Authentication Response
        # -------------------------------------------------

        response = {

            "responder":

                responder.rsu_id

                if isinstance(responder, RSU)

                else responder.real_id,

            "responder_pseudonym":

                responder_identity,

            "timestamp":

                timestamp,

            "nonce":

                nonce,

            "signature":

                signature,

            "kem_public_key":

                responder.kem_pk

        }

        return response


    # =====================================================
    # Verify Authentication Response (Message M2)
    # =====================================================

    def verify_auth_response(
        self,
        initiator,
        responder,
        response
    ):
        """
        Verify authentication response.
        """

        print("\nVerifying Authentication Response...")

        # -------------------------------------------------
        # Timestamp Validation
        # -------------------------------------------------

        current_time = int(time.time())

        if abs(current_time - response["timestamp"]) > self.timestamp_window:

            print("Authentication Failed : Response Timeout")

            self.failed_authentications += 1

            return False

        # -------------------------------------------------
        # Replay Protection
        # -------------------------------------------------

        nonce_hex = response["nonce"].hex()

        if nonce_hex in self.used_nonces:

            print("Authentication Failed : Replay Attack")

            self.failed_authentications += 1

            return False

        self.used_nonces.add(

            nonce_hex

        )

        # -------------------------------------------------
        # Responder Identity
        # -------------------------------------------------

        responder_identity = (

            responder.current_pseudonym

            if isinstance(responder, Vehicle)

            else responder.rsu_id

        )

        # -------------------------------------------------
        # Build Signed Message
        # -------------------------------------------------

        message = (

            str(responder_identity)

            + str(initiator.current_pseudonym)

            + str(response["timestamp"])

            + nonce_hex

        ).encode()

        # -------------------------------------------------
        # Verify Dilithium Signature
        # -------------------------------------------------

        if not dilithium.verify_signature(

            responder.sig_pk,

            message,

            response["signature"]

        ):

            print("Authentication Failed : Invalid Signature")

            self.failed_authentications += 1

            return False

        print("Authentication Response Verified")

        return True
            # =====================================================
    # Establish PQC Session Key (Message M3)
    # =====================================================

    def establish_session_key(
        self,
        initiator,
        responder,
        responder_public_key
    ):
        """
        Establish ML-KEM session key.
        """

        print("\nEstablishing Session Key...")

        # -------------------------------------------------
        # ML-KEM Encapsulation
        # -------------------------------------------------

        ciphertext, shared_secret_sender = kyber.encapsulate(
            responder_public_key
        )

        # -------------------------------------------------
        # ML-KEM Decapsulation
        # -------------------------------------------------

        shared_secret_receiver = kyber.decapsulate(
            responder.kem_sk,
            ciphertext
        )

        # -------------------------------------------------
        # Session Context
        # -------------------------------------------------

        responder_identity = (

            responder.current_pseudonym

            if isinstance(responder, Vehicle)

            else responder.rsu_id

        )

        context = (

            initiator.current_pseudonym

            + responder_identity

        )

        # -------------------------------------------------
        # Derive Session Keys
        # -------------------------------------------------

                # -------------------------------------------------
        # Context-Aware Session Key Derivation
        # -------------------------------------------------

        session_nonce = qrng.generate_random_bytes(16).hex()

        road_id = "RS-001"

        pseudonym = initiator.current_pseudonym

        timestamp = str(int(time.time()))

        sender_key = self.context_key_manager.derive_session_key(
            shared_secret=shared_secret_sender,
            session_nonce=session_nonce,
            road_id=road_id,
            pseudonym=pseudonym,
            timestamp=timestamp
        )

        receiver_key = self.context_key_manager.derive_session_key(
            shared_secret=shared_secret_receiver,
            session_nonce=session_nonce,
            road_id=road_id,
            pseudonym=pseudonym,
            timestamp=timestamp
        )

        # -------------------------------------------------
        # Verify Session Key
        # -------------------------------------------------

        if sender_key != receiver_key:

            print("Session Key Establishment Failed")

            self.failed_authentications += 1

            return False
        # -------------------------------------------------
        # Verify Session Key
        # -------------------------------------------------

        if sender_key != receiver_key:

            print("Session Key Establishment Failed")

            self.failed_authentications += 1

            return False

        # -------------------------------------------------
        # Store Session
        # -------------------------------------------------

        session = {

            "session_key": sender_key,

            "ciphertext": ciphertext,

            "created_at": time.time(),

            "expires_at": time.time() + self.session_timeout

        }

        self.active_sessions[

            (

                initiator.real_id,

                responder.rsu_id

                if isinstance(responder, RSU)

                else responder.real_id

            )

        ] = session

        print("Session Key Established")

        return True


    # =====================================================
    # Complete Mutual Authentication
    # =====================================================

    def authenticate(
        self,
        sender,
        receiver
    ):
        """
        Execute complete PQC Mutual Authentication.
        """

        print("\n" + "=" * 70)
        print("PQC MUTUAL AUTHENTICATION")
        print("=" * 70)

        print(f"Initiator : {sender.real_id}")

        if isinstance(receiver, Vehicle):

            print(f"Responder : {receiver.real_id}")

        else:

            print(f"Responder : {receiver.rsu_id}")

        print("-" * 70)

        start = time.perf_counter()

        # =================================================
        # Message M1
        # =================================================

        request = self.create_auth_request(

            sender,

            receiver

        )

        if not self.verify_auth_request(

            receiver,

            request

        ):

            print("Authentication Failed during Message M1")

            return False

        # =================================================
        # Message M2
        # =================================================

        response = self.create_auth_response(

            receiver,

            sender

        )

        if not self.verify_auth_response(

            sender,

            receiver,

            response

        ):

            print("Authentication Failed during Message M2")

            return False
                # =====================================================
        # ML-KEM
        # =====================================================

        print("Starting ML-KEM Key Encapsulation...")
        # =================================================
        # Message M3
        # =================================================

        if not self.establish_session_key(

            sender,

            receiver,

            response["kem_public_key"]

        ):

            print("Authentication Failed during Session Establishment")

            return False
        print("ML-KEM Completed")
        # =====================================================
# Session Key
# =====================================================

        print("Secure Session Key Established")
        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.authentication_times.append(

            elapsed

        )

        self.successful_authentications += 1

        # =================================================
        # Authentication Log
        # =================================================

        self.authentication_logs.append({

            "sender":

                sender.real_id,

            "receiver":

                receiver.rsu_id

                if isinstance(receiver, RSU)

                else receiver.real_id,

            "sender_pid":

                sender.current_pseudonym,

            "authentication_confidence_token":

                request["act"],

            "timestamp":

                request["timestamp"],

            "authentication_time":

                elapsed

        })

        print("\n✓ Mutual Authentication Successful")

        print(f"Authentication Time : {elapsed:.3f} ms")

        print("=" * 70)

        return True
        # =====================================================
# Network Authentication
# =====================================================

    
    def authenticate_network(
        self,
        vehicles,
        rsus
    ):
        """
        Perform authentication across the network.
        """

        print("\n")
        print("=" * 70)
        print("NETWORK AUTHENTICATION")
        print("=" * 70)

    # Vehicle ↔ Vehicle

        if len(vehicles) >= 2:

            self.authenticate(

                vehicles[0],

                vehicles[1]

            )

    # Vehicle ↔ RSU

        if len(vehicles) >= 1 and len(rsus) >= 1:

            self.authenticate(

                vehicles[0],

                rsus[0]
 
            )

        if len(vehicles) >= 2 and len(rsus) >= 1:

            self.authenticate(

                vehicles[1],

                rsus[0]

            )
            # =====================================================
        # Get Active Session
    # =====================================================

        # =====================================================
    # Get Active Session
    # =====================================================

    def get_session(
        self,
        initiator_id,
        responder_id
    ):
        """
        Return an active session if available.
        """

        session = self.active_sessions.get(
            (
                initiator_id,
                responder_id
            )
        )

        if session is None:
            return None

        if session["expires_at"] < time.time():

            del self.active_sessions[
                (
                    initiator_id,
                    responder_id
                )
            ]

            return None

        return session


    # =====================================================
    # Compatibility Wrapper
    # =====================================================

    def get_session_key(
        self,
        initiator_id,
        responder_id
    ):
        """
        Return only the session key for compatibility
        with Secure Message Transfer.
        """


        session = self.get_session(
            initiator_id,
            responder_id
        )

        if session is None:
            return None

        return session["session_key"]


    # =====================================================
    # Remove Session
    # =====================================================

    def remove_session(
        self,
        initiator_id,
        responder_id
    ):
        """
        Remove an active session.
        """

        self.active_sessions.pop(

            (

                initiator_id,

                responder_id

            ),

            None

        )


    # =====================================================
    # Clear All Sessions
    # =====================================================

    def clear_sessions(self):
        """
        Remove every active session.
        """

        self.active_sessions.clear()

        print("All Active Sessions Cleared")


    # =====================================================
    # Show Authentication Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)

        print("MUTUAL AUTHENTICATION STATISTICS")

        print("=" * 70)

        print(

            f"Successful Authentications : "

            f"{self.successful_authentications}"

        )

        print(

            f"Failed Authentications     : "

            f"{self.failed_authentications}"

        )

        print(

            f"Active Sessions            : "

            f"{len(self.active_sessions)}"

        )

        if self.authentication_times:

            average = (

                sum(self.authentication_times)

                /

                len(self.authentication_times)

            )

        else:

            average = 0.0

        print(

            f"Average Authentication Time : "

            f"{average:.3f} ms"

        )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        average = (

            sum(self.authentication_times)

            /

            len(self.authentication_times)

            if self.authentication_times

            else 0.0

        )

        return {

            "successful_authentications":

                self.successful_authentications,

            "failed_authentications":

                self.failed_authentications,

            "active_sessions":

                len(self.active_sessions),

            "average_authentication_time":

                average,

            "authentication_times":

                self.authentication_times.copy(),

            "authentication_logs":

                self.authentication_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.authentication_times.clear()

        self.authentication_logs.clear()

        self.active_sessions.clear()

        self.used_nonces.clear()

        self.used_timestamps.clear()

        self.successful_authentications = 0

        self.failed_authentications = 0

        print("Mutual Authentication Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"MutualAuthentication("

            f"Success={self.successful_authentications}, "

            f"Failed={self.failed_authentications}, "

            f"Sessions={len(self.active_sessions)})"

        )