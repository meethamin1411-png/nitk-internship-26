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

This protocol is the foundation for

• Secure Messaging
• V2V Communication
• V2I Communication
• City Simulation

Author : Meeth Amin
=========================================================
"""

import time

from crypto import qrng
from crypto import dilithium
from crypto import kyber

from models import Vehicle
from models import RSU
from models import TrustedAuthority


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
            # =====================================================
    # Create Authentication Request (Message M1)
    # =====================================================

    def create_auth_request(
        self,
        sender,
        receiver
    ):
        """
        Create the first authentication message.

        Works for:
            Vehicle -> Vehicle
            Vehicle -> RSU
        """

        print("\nCreating Authentication Request...")

        # ---------------------------------------------
        # Timestamp
        # ---------------------------------------------

        timestamp = int(time.time())

        # ---------------------------------------------
        # QRNG Nonce
        # ---------------------------------------------

        nonce = qrng.generate_random_bytes(16)

        # ---------------------------------------------
        # Message to be Signed
        # ---------------------------------------------

        message = (

            str(sender.current_pseudonym)

            + str(receiver.rsu_id if isinstance(receiver, RSU)
                  else receiver.current_pseudonym)

            + str(timestamp)

            + nonce.hex()

        ).encode()

        # ---------------------------------------------
        # Dilithium Signature
        # ---------------------------------------------

        signature = dilithium.sign_message(

            sender.sig_sk,

            message

        )

        # ---------------------------------------------
        # Authentication Request
        # ---------------------------------------------

        request = {

            "sender_id":

                sender.real_id,

            "sender_pseudonym":

                sender.current_pseudonym,

            "receiver":

                receiver.rsu_id

                if isinstance(receiver, RSU)

                else receiver.real_id,

            "timestamp":

                timestamp,

            "nonce":

                nonce,

            "signature":

                signature,

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
        # Lookup Vehicle using Pseudonym
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
        # Reconstruct Signed Message
        # -------------------------------------------------

        receiver_identity = (

            receiver.rsu_id

            if isinstance(receiver, RSU)

            else receiver.current_pseudonym

        )

        message = (

            str(request["sender_pseudonym"])

            + str(receiver_identity)

            + str(request["timestamp"])

            + nonce_hex

        ).encode()

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
        Create authentication response.
        """

        print("\nCreating Authentication Response...")

        timestamp = int(time.time())

        nonce = qrng.generate_random_bytes(16)

        message = (

            str(responder.current_pseudonym if isinstance(responder, Vehicle)
                else responder.rsu_id)

            + str(initiator.current_pseudonym)

            + str(timestamp)

            + nonce.hex()

        ).encode()

        signature = dilithium.sign_message(

            responder.sig_sk,

            message

        )

        response = {

            "responder":

                responder.rsu_id

                if isinstance(responder, RSU)

                else responder.real_id,

            "responder_pseudonym":

                responder.current_pseudonym

                if isinstance(responder, Vehicle)

                else responder.rsu_id,

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
        Verify the authentication response.
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

            print("Authentication Failed : Replay Detected")

            self.failed_authentications += 1

            return False

        self.used_nonces.add(nonce_hex)

        # -------------------------------------------------
        # Build Signed Message
        # -------------------------------------------------

        responder_identity = (

            responder.current_pseudonym

            if isinstance(responder, Vehicle)

            else responder.rsu_id

        )

        message = (

            str(responder_identity)

            + str(initiator.current_pseudonym)

            + str(response["timestamp"])

            + nonce_hex

        ).encode()

        # -------------------------------------------------
        # Signature Verification
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

        # -----------------------------
        # ML-KEM Encapsulation
        # -----------------------------

        ciphertext, shared_secret_sender = (

            kyber.encapsulate(

                responder_public_key

            )

        )

        # -----------------------------
        # ML-KEM Decapsulation
        # -----------------------------

        shared_secret_receiver = (

            kyber.decapsulate(

                responder.kem_sk,

                ciphertext

            )

        )

        # -----------------------------
        # Session Context
        # -----------------------------

        context = (

            initiator.current_pseudonym

            +

            (

                responder.current_pseudonym

                if isinstance(responder, Vehicle)

                else responder.rsu_id

            )

        )

        # -----------------------------
        # Derive Session Keys
        # -----------------------------

        sender_key = kyber.derive_session_key(

            shared_secret_sender,

            context

        )

        receiver_key = kyber.derive_session_key(

            shared_secret_receiver,

            context

        )

        if sender_key != receiver_key:

            print("Session Key Establishment Failed")

            return False

        # -----------------------------
        # Store Active Session
        # -----------------------------

        session = {

            "session_key": sender_key,

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

        # -------------------------------------------------
        # Message M1
        # -------------------------------------------------

        request = self.create_auth_request(

            sender,

            receiver

        )

        if not self.verify_auth_request(

            receiver,

            request

        ):

            return False

        # -------------------------------------------------
        # Message M2
        # -------------------------------------------------

        response = self.create_auth_response(

            receiver,

            sender

        )

        if not self.verify_auth_response(

            sender,

            receiver,

            response

        ):

            return False

        # -------------------------------------------------
        # Message M3
        # -------------------------------------------------

        if not self.establish_session_key(

            sender,

            receiver,

            response["kem_public_key"]

        ):

            return False

        elapsed = (

            time.perf_counter() - start

        ) * 1000

        self.authentication_times.append(

            elapsed

        )

        self.successful_authentications += 1

        self.authentication_logs.append({

            "sender":

                sender.real_id,

            "receiver":

                receiver.rsu_id

                if isinstance(receiver, RSU)

                else receiver.real_id,

            "time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print("\n✓ Mutual Authentication Successful")

        print(f"Authentication Time : {elapsed:.3f} ms")

        print("=" * 70)

        return True


       # =====================================================
    # Authenticate Network
    # =====================================================

    def authenticate_network(
        self,
        vehicles,
        rsus=None
    ):
        """
        Authenticate neighbouring vehicles and RSUs.
        """

        print("\n" + "=" * 70)
        print("NETWORK AUTHENTICATION")
        print("=" * 70)

        # ---------------------------------------------
        # Vehicle ↔ Vehicle
        # ---------------------------------------------

        for i in range(len(vehicles) - 1):

            self.authenticate(

                vehicles[i],

                vehicles[i + 1]

            )

        # ---------------------------------------------
        # Vehicle ↔ RSU
        # ---------------------------------------------

        if rsus is not None:

            for index, vehicle in enumerate(vehicles):

                rsu = rsus[index % len(rsus)]

                self.authenticate(

                    vehicle,

                    rsu

                )

      
     # =====================================================
    # Get Active Session
    # =====================================================
    def get_session(
        self,
        sender_id,
        receiver_id
    ):
        """
        Return an active session if available.
        """

        return self.active_sessions.get(

            (sender_id, receiver_id),

            None

        )


    # =====================================================
    # Get Session Key
    # =====================================================

    def get_session_key(
        self,
        sender_id,
        receiver_id
    ):
        """
        Return only the session key.
        """

        session = self.get_session(

            sender_id,

            receiver_id

        )

        if session is None:

            return None

        return session["session_key"]


   
    # =====================================================
    # Remove Expired Sessions
    # =====================================================

    def remove_expired_sessions(self):
        """
        Remove expired authentication sessions.
        """

        current_time = time.time()

        expired = []

        for session_id, session in self.active_sessions.items():

            if session["expires_at"] <= current_time:

                expired.append(session_id)

        for session_id in expired:

            del self.active_sessions[session_id]

        if expired:

            print(

                f"{len(expired)} expired session(s) removed."

            )


    # =====================================================
    # Display Authentication Statistics
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

        print(

            f"Recorded Executions        : "

            f"{len(self.authentication_times)}"

        )

        if self.authentication_times:

            average = (

                sum(self.authentication_times)

                /

                len(self.authentication_times)

            )

            print(

                f"Average Authentication Time : "

                f"{average:.3f} ms"

            )

        else:

            print(

                "Average Authentication Time : 0.000 ms"

            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        if self.authentication_times:

            average = (

                sum(self.authentication_times)

                /

                len(self.authentication_times)

            )

        else:

            average = 0.0

        return {

            "successful":

                self.successful_authentications,

            "failed":

                self.failed_authentications,

            "active_sessions":

                len(self.active_sessions),

            "average_time":

                average,

            "authentication_times":

                self.authentication_times.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.authentication_logs.clear()

        self.authentication_times.clear()

        self.active_sessions.clear()

        self.used_nonces.clear()

        self.used_timestamps.clear()

        self.successful_authentications = 0

        self.failed_authentications = 0

        print("Authentication Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"MutualAuthentication("

            f"Sessions={len(self.active_sessions)}, "

            f"Success={self.successful_authentications}, "

            f"Failed={self.failed_authentications})"

        )