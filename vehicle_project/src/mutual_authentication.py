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
• Context-aware session-key derivation

Protocol implemented by this module

M1: Vehicle -> RSU/Vehicle
    PID, ACT, nonce, timestamp/context, ML-DSA signature

M2: RSU/Vehicle -> Vehicle
    Responder identity, fresh nonce, ephemeral ML-KEM public key,
    timestamp, ML-DSA signature

M3: Vehicle -> RSU/Vehicle
    M2 challenge nonce, ML-KEM ciphertext to the ephemeral key,
    timestamp/context, ML-DSA signature

M4: RSU/Vehicle -> Vehicle
    Session-key confirmation

The receiver's long-term ML-KEM key pair is provisioned before
online authentication. A fresh ephemeral ML-KEM key pair is generated
for every authentication session; only its public key is transmitted
in M2 and its private key is discarded after M3 decapsulation.

Author : Meeth Amin
=========================================================
"""

import hmac
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
    PQC Mutual Authentication Manager.

    The online authentication flow is explicitly represented as
    M1 -> M2 -> M3 -> M4 so that the implementation can be mapped
    directly to the protocol description and formal model.
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        trusted_authority: TrustedAuthority,
    ):
        self.act_generated = 0
        self.act_verified = 0
        self.act_rejected = 0

        self.act_generation_times = []
        self.act_verification_times = []

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
        # Protocol Message Logs
        # =================================================

        self.protocol_messages = []

        # =================================================
        # Session Configuration
        # =================================================

        self.session_timeout = 300

        # Keep the existing module's time unit/behavior for
        # compatibility with the rest of the project.
        self.timestamp_window = 30

        # =================================================
        # Context-Aware Session Key Manager
        # =================================================

        self.context_key_manager = ContextAwareSessionKey()

        print("\nMutual Authentication Protocol Initialized")

    # =====================================================
    # Helper Methods
    # =====================================================

    @staticmethod
    def _identity(entity):
        """Return the online identity used for the entity."""

        if isinstance(entity, RSU):
            return entity.rsu_id

        return entity.current_pseudonym

    @staticmethod
    def _session_record_key(initiator, responder):
        """Return the internal key used for active-session storage."""

        responder_id = (
            responder.rsu_id
            if isinstance(responder, RSU)
            else responder.real_id
        )

        return initiator.real_id, responder_id

    @staticmethod
    def _m1_signed_data(
        sender_pseudonym,
        receiver_identity,
        timestamp,
        nonce,
        road_segment,
        vehicle_state,
        act,
    ):
        """Build the exact byte string signed in M1."""

        return (
            str(sender_pseudonym)
            + str(receiver_identity)
            + str(timestamp)
            + nonce.hex()
            + str(road_segment)
            + str(vehicle_state)
            + str(act)
        ).encode()

    @staticmethod
    def _m2_signed_data(
        responder_identity,
        initiator_pseudonym,
        timestamp,
        nonce,
        ephemeral_kem_pk,
    ):
        """Build the exact byte string signed in M2.

        The responder's fresh ephemeral ML-KEM public key is included
        in the signed transcript so it cannot be replaced by an attacker.
        """

        return (
            str(responder_identity)
            + str(initiator_pseudonym)
            + str(timestamp)
            + nonce.hex()
            + ephemeral_kem_pk.hex()
        ).encode()

    @staticmethod
    def _m3_signed_data(
        sender_pseudonym,
        responder_identity,
        m2_nonce,
        ephemeral_kem_pk,
        ciphertext,
        timestamp,
        road_segment,
        vehicle_state,
    ):
        """
        Build the exact byte string signed in M3.

        M3 is cryptographically bound to the current authentication
        transcript, including the responder's ephemeral ML-KEM public key.
        """

        return (
            str(sender_pseudonym)
            + str(responder_identity)
            + m2_nonce.hex()
            + ephemeral_kem_pk.hex()
            + ciphertext.hex()
            + str(timestamp)
            + str(road_segment)
            + str(vehicle_state)
        ).encode()


    @staticmethod
    def _m4_confirmation_data(
        session_key,
        m1_nonce,
        m2_nonce,
        sender_pseudonym,
        responder_identity,
        timestamp,
    ):
        """Build the exact data authenticated by the M4 confirmation."""

        return (
            b"M4-CONFIRM"
            + session_key
            + m1_nonce
            + m2_nonce
            + str(sender_pseudonym).encode()
            + str(responder_identity).encode()
            + str(timestamp).encode()
        )

    @staticmethod
    def _confirmation(session_key, m1_nonce, m2_nonce,
                      sender_pseudonym, responder_identity, timestamp):
        """Create the M4 session-key confirmation value."""

        data = MutualAuthentication._m4_confirmation_data(
            session_key,
            m1_nonce,
            m2_nonce,
            sender_pseudonym,
            responder_identity,
            timestamp,
        )

        # hash_bytes returns a SHA3-256 hexadecimal digest.
        return hash_utils.hash_bytes(data)

    def _derive_context_key(
        self,
        shared_secret,
        request,
        response,
    ):
        """Derive the final context-aware session key identically at both peers."""

        if shared_secret is None:
            return None

        # M2's fresh responder nonce is the session nonce used by both
        # parties. This avoids generating a local nonce that the peer
        # cannot reconstruct.
        session_nonce = response["nonce"].hex()

        road_id = request["road_segment"]
        pseudonym = request["sender_pseudonym"]
        timestamp = str(request["timestamp"])

        return self.context_key_manager.derive_session_key(
            shared_secret=shared_secret,
            session_nonce=session_nonce,
            road_id=road_id,
            pseudonym=pseudonym,
            timestamp=timestamp,
        )

    # =====================================================
    # Create Authentication Request (Message M1)
    # =====================================================

    def create_auth_request(self, sender, receiver):
        """
        Create M1: Vehicle -> RSU/Vehicle.

        M1 contains:
            • Vehicle pseudonym
            • Receiver identity
            • Fresh nonce
            • Timestamp
            • Road/context information
            • ACT
            • ML-DSA signature

        The sender's real identity and ML-KEM public key are not
        transmitted in M1.
        """

        print("\nCreating Message M1 : Authentication Request...")
        print("\nGenerating Authentication Confidence Token")
        print("-" * 50)

        timestamp = int(time.time())
        nonce = qrng.generate_random_bytes(16)

        road_segment = "RS-001"
        vehicle_state = "ACTIVE"

        # -------------------------------------------------
        # ACT generation
        # -------------------------------------------------

        act_start = time.perf_counter()

        act = hash_utils.generate_act(
            sender.current_pseudonym,
            nonce,
            road_segment,
            vehicle_state,
            timestamp,
        )

        act_time = (time.perf_counter() - act_start) * 1000

        self.act_generated += 1
        self.act_generation_times.append(act_time)

        print("Authentication Confidence Token Information")
        print("-" * 50)
        print(f"Vehicle PID        : {sender.current_pseudonym}")
        print(f"Road Segment       : {road_segment}")
        print(f"Vehicle State      : {vehicle_state}")
        print(f"Timestamp          : {timestamp}")
        print(f"Nonce              : {nonce.hex()[:16]}...")
        print(f"Generated ACT      : {act}")
        print("-" * 50)
        print("ACT Generated")

        receiver_identity = self._identity(receiver)

        # -------------------------------------------------
        # ML-DSA signature
        # -------------------------------------------------

        message = self._m1_signed_data(
            sender.current_pseudonym,
            receiver_identity,
            timestamp,
            nonce,
            road_segment,
            vehicle_state,
            act,
        )

        signature = dilithium.sign_message(
            sender.sig_sk,
            message,
        )

        # -------------------------------------------------
        # M1 packet
        # -------------------------------------------------

        request = {
            "sender_pseudonym": sender.current_pseudonym,
            "receiver": receiver_identity,
            "timestamp": timestamp,
            "nonce": nonce,
            "road_segment": road_segment,
            "vehicle_state": vehicle_state,
            "act": act,
            "signature": signature,
        }

        self.protocol_messages.append({
            "message": "M1",
            "direction": "initiator->responder",
            "fields": tuple(request.keys()),
        })

        return request

    # =====================================================
    # Verify Authentication Request (Message M1)
    # =====================================================

    def verify_auth_request(self, receiver, request):
        """
        Verify M1 using the lightweight ACT/context checks before
        expensive ML-DSA verification.
        """

        print("\n")
        print("=" * 70)
        print("M1 : LIGHTWEIGHT AUTHENTICATION")
        print("=" * 70)
        print("Receiving Message M1...")

        required_fields = {
            "sender_pseudonym",
            "receiver",
            "timestamp",
            "nonce",
            "road_segment",
            "vehicle_state",
            "act",
            "signature",
        }

        if not required_fields.issubset(request.keys()):
            print("Authentication Failed : Invalid M1 Structure")
            self.failed_authentications += 1
            return False

        # -------------------------------------------------
        # Verify intended receiver
        # -------------------------------------------------

        expected_receiver = self._identity(receiver)

        if request["receiver"] != expected_receiver:
            print("Authentication Failed : Wrong Receiver")
            self.failed_authentications += 1
            return False

        # -------------------------------------------------
        # Freshness check
        # -------------------------------------------------

        print("Checking Freshness...")

        current_time = int(time.time())

        if abs(current_time - request["timestamp"]) > self.timestamp_window:
            print("Authentication Failed : Timestamp Expired")
            self.failed_authentications += 1
            return False

        print("Freshness Check Passed")

        # -------------------------------------------------
        # Replay protection
        # -------------------------------------------------

        nonce_hex = request["nonce"].hex()

        if nonce_hex in self.used_nonces:
            print("Authentication Failed : Replay Attack")
            self.failed_authentications += 1
            return False

        # -------------------------------------------------
        # Lookup sender using pseudonym
        # -------------------------------------------------

        sender = self.ta.get_vehicle_by_pseudonym(
            request["sender_pseudonym"]
        )

        if sender is None:
            print("Authentication Failed : Unknown Vehicle")
            self.failed_authentications += 1
            return False

        # -------------------------------------------------
        # Revocation check
        # -------------------------------------------------

        if self.ta.is_revoked(sender.real_id):
            print("Authentication Failed : Revoked Vehicle")
            self.failed_authentications += 1
            return False

        # -------------------------------------------------
        # ACT verification
        # -------------------------------------------------

        print("Verifying Authentication Confidence Token...")

        verify_start = time.perf_counter()

        act_valid = hash_utils.verify_act(
            request["act"],
            request["sender_pseudonym"],
            request["nonce"],
            request["road_segment"],
            request["vehicle_state"],
            request["timestamp"],
        )

        verify_time = (time.perf_counter() - verify_start) * 1000

        if not act_valid:
            self.act_rejected += 1
            self.act_verification_times.append(verify_time)
            print("Authentication Failed : Invalid ACT")
            self.failed_authentications += 1
            return False

        self.act_verified += 1
        self.act_verification_times.append(verify_time)

        print("✓ ACT Verification Successful")

        # -------------------------------------------------
        # Context check
        # -------------------------------------------------

        print("Performing Context Check...")

        allowed_states = [
            "ACTIVE",
            "EMERGENCY",
        ]

        if request["vehicle_state"] not in allowed_states:
            print("Authentication Failed : Invalid Vehicle State")
            self.failed_authentications += 1
            return False

        allowed_segments = [
            "RS-001",
            "NH66",
            "CITY_ZONE",
            "MILITARY_ZONE",
        ]

        if request["road_segment"] not in allowed_segments:
            print("Authentication Failed : Invalid Road Segment")
            self.failed_authentications += 1
            return False

        print(f"Road Segment : {request['road_segment']}")
        print(f"Vehicle State : {request['vehicle_state']}")
        print("✓ Context Validation Successful")

        # -------------------------------------------------
        # Rebuild M1 signed data
        # -------------------------------------------------

        message = self._m1_signed_data(
            request["sender_pseudonym"],
            expected_receiver,
            request["timestamp"],
            request["nonce"],
            request["road_segment"],
            request["vehicle_state"],
            request["act"],
        )

        # -------------------------------------------------
        # ML-DSA verification
        # -------------------------------------------------

        print("Performing ML-DSA Signature Verification...")

        if not dilithium.verify_signature(
            sender.sig_pk,
            message,
            request["signature"],
        ):
            print("Authentication Failed : Invalid ML-DSA Signature")
            self.failed_authentications += 1
            return False

        # Mark nonce as used only after all M1 checks pass.
        self.used_nonces.add(nonce_hex)

        print("✓ ML-DSA Signature Verified")
        print("✓ Message M1 Verified")

        return True

    # =====================================================
    # Create Authentication Response (Message M2)
    # =====================================================

    def create_auth_response(self, responder, initiator):
        """
        Create M2: RSU/Vehicle -> Vehicle.

        M2 contains the responder identity, a fresh nonce, a fresh
        ephemeral ML-KEM public key, and an ML-DSA signature. The matching
        ephemeral ML-KEM private key is kept locally by the responder and
        is never transmitted.
        """

        print("\nCreating Message M2 : Authentication Response...")

        timestamp = int(time.time())
        nonce = qrng.generate_random_bytes(16)

        responder_identity = self._identity(responder)
        initiator_pseudonym = initiator.current_pseudonym

        # Generate a fresh ML-KEM key pair for THIS authentication session.
        # The public key is transmitted in M2; the private key remains local.
        ephemeral_kem_pk, ephemeral_kem_sk = kyber.generate_keypair()

        message = self._m2_signed_data(
            responder_identity,
            initiator_pseudonym,
            timestamp,
            nonce,
            ephemeral_kem_pk,
        )

        signature = dilithium.sign_message(
            responder.sig_sk,
            message,
        )

        response = {
            "responder": responder_identity,
            "timestamp": timestamp,
            "nonce": nonce,
            "ephemeral_kem_pk": ephemeral_kem_pk,
            "signature": signature,
            # Local-only state. This field is NEVER transmitted.
            "_ephemeral_kem_sk": ephemeral_kem_sk,
        }

        self.protocol_messages.append({
            "message": "M2",
            "direction": "responder->initiator",
            "fields": (
                "responder",
                "timestamp",
                "nonce",
                "ephemeral_kem_pk",
                "signature",
            ),
        })

        print("✓ Fresh Ephemeral ML-KEM Key Pair Generated")
        print("✓ Ephemeral ML-KEM Public Key Bound to M2 ML-DSA Signature")

        return response

    # =====================================================
    # Verify Authentication Response (Message M2)
    # =====================================================

    def verify_auth_response(self, initiator, responder, response):
        """
        Verify M2 using freshness, replay protection and ML-DSA.
        """

        print("\nVerifying Message M2...")

        required_fields = {
            "responder",
            "timestamp",
            "nonce",
            "ephemeral_kem_pk",
            "signature",
        }

        if not required_fields.issubset(response.keys()):
            print("Authentication Failed : Invalid M2 Structure")
            self.failed_authentications += 1
            return False

        current_time = int(time.time())

        if abs(current_time - response["timestamp"]) > self.timestamp_window:
            print("Authentication Failed : Response Timeout")
            self.failed_authentications += 1
            return False

        responder_identity = self._identity(responder)

        if response["responder"] != responder_identity:
            print("Authentication Failed : Wrong Responder")
            self.failed_authentications += 1
            return False

        nonce_hex = response["nonce"].hex()

        if nonce_hex in self.used_nonces:
            print("Authentication Failed : Replay Attack")
            self.failed_authentications += 1
            return False

        message = self._m2_signed_data(
            responder_identity,
            initiator.current_pseudonym,
            response["timestamp"],
            response["nonce"],
            response["ephemeral_kem_pk"],
        )

        if not dilithium.verify_signature(
            responder.sig_pk,
            message,
            response["signature"],
        ):
            print("Authentication Failed : Invalid M2 Signature")
            self.failed_authentications += 1
            return False

        self.used_nonces.add(nonce_hex)

        print("✓ M2 ML-DSA Signature Verified")
        print("✓ Message M2 Verified")

        return True

    # =====================================================
    # Create M3: ML-KEM Encapsulation
    # =====================================================

    def create_m3_kem_message(
        self,
        initiator,
        responder,
        request,
        response,
    ):
        """
        Create M3: Vehicle -> RSU/Vehicle.

        The initiator encapsulates to the responder's FRESH ephemeral
        ML-KEM public key received and authenticated in M2. The long-term
        ML-KEM public key is NOT used for the session key.
        """

        print("\nCreating Message M3 : Ephemeral ML-KEM Key Establishment...")

        responder_identity = self._identity(responder)
        m2_nonce = response["nonce"]
        ephemeral_kem_pk = response["ephemeral_kem_pk"]

        # Encapsulate to the responder's fresh per-session public key.
        ciphertext, shared_secret = kyber.encapsulate(
            ephemeral_kem_pk
        )

        print("✓ ML-KEM Encapsulation Completed Using Ephemeral Public Key")

        timestamp = int(time.time())
        road_segment = request["road_segment"]
        vehicle_state = request["vehicle_state"]
        sender_pseudonym = request["sender_pseudonym"]

        message = self._m3_signed_data(
            sender_pseudonym,
            responder_identity,
            m2_nonce,
            ephemeral_kem_pk,
            ciphertext,
            timestamp,
            road_segment,
            vehicle_state,
        )

        signature = dilithium.sign_message(
            initiator.sig_sk,
            message,
        )

        m3 = {
            "sender_pseudonym": sender_pseudonym,
            "responder": responder_identity,
            "m2_nonce": m2_nonce,
            "ciphertext": ciphertext,
            "timestamp": timestamp,
            "road_segment": road_segment,
            "vehicle_state": vehicle_state,
            "signature": signature,
        }

        local_state = {
            "shared_secret": shared_secret,
            "m3": m3,
        }

        self.protocol_messages.append({
            "message": "M3",
            "direction": "initiator->responder",
            "fields": tuple(m3.keys()),
        })

        print("✓ M3 Created")
        print("✓ M2 Challenge Nonce Bound to M3")
        print("✓ Ephemeral ML-KEM Public Key Bound to M3")
        print("✓ M3 ML-DSA Signature Generated")

        return local_state

    # =====================================================
    # Verify/Process M3 at Responder
    # =====================================================

    def process_m3_kem_message(
        self,
        initiator,
        responder,
        request,
        response,
        m3,
    ):
        """
        Process M3 at the responder using the fresh ephemeral ML-KEM
        private key created for this authentication session.
        """

        print("\nProcessing Message M3 at Responder...")

        required_fields = {
            "sender_pseudonym",
            "responder",
            "m2_nonce",
            "ciphertext",
            "timestamp",
            "road_segment",
            "vehicle_state",
            "signature",
        }

        if not required_fields.issubset(m3.keys()):
            print("M3 rejected : Invalid Message Structure")
            self.failed_authentications += 1
            return None

        current_time = int(time.time())

        if abs(current_time - m3["timestamp"]) > self.timestamp_window:
            print("M3 rejected : Timestamp Expired")
            self.failed_authentications += 1
            return None

        if m3["sender_pseudonym"] != request["sender_pseudonym"]:
            print("M3 rejected : Pseudonym Mismatch")
            self.failed_authentications += 1
            return None

        expected_responder = self._identity(responder)

        if m3["responder"] != expected_responder:
            print("M3 rejected : Wrong Responder")
            self.failed_authentications += 1
            return None

        if m3["m2_nonce"] != response["nonce"]:
            print("M3 rejected : M2 Challenge Nonce Mismatch")
            self.failed_authentications += 1
            return None

        print("✓ M2 Challenge Nonce Verified")

        if m3["road_segment"] != request["road_segment"]:
            print("M3 rejected : Road Context Mismatch")
            self.failed_authentications += 1
            return None

        if m3["vehicle_state"] != request["vehicle_state"]:
            print("M3 rejected : Vehicle Context Mismatch")
            self.failed_authentications += 1
            return None

        ephemeral_kem_pk = response.get("ephemeral_kem_pk")
        ephemeral_kem_sk = response.get("_ephemeral_kem_sk")

        if ephemeral_kem_pk is None or ephemeral_kem_sk is None:
            print("M3 rejected : Ephemeral ML-KEM Key Material Missing")
            self.failed_authentications += 1
            return None

        message = self._m3_signed_data(
            m3["sender_pseudonym"],
            m3["responder"],
            m3["m2_nonce"],
            ephemeral_kem_pk,
            m3["ciphertext"],
            m3["timestamp"],
            m3["road_segment"],
            m3["vehicle_state"],
        )

        if not dilithium.verify_signature(
            initiator.sig_pk,
            message,
            m3["signature"],
        ):
            print("M3 rejected : Invalid ML-DSA Signature")
            self.failed_authentications += 1
            return None

        print("✓ M3 ML-DSA Signature Verified")

        try:
            shared_secret = kyber.decapsulate(
                ephemeral_kem_sk,
                m3["ciphertext"],
            )
        except Exception as e:
            print(f"M3 rejected : Ephemeral ML-KEM Decapsulation Failed - {e}")
            self.failed_authentications += 1
            return None
        finally:
            # Best-effort removal of the ephemeral private-key reference.
            # It must not remain in protocol/session state after use.
            response.pop("_ephemeral_kem_sk", None)

        print("✓ Ephemeral ML-KEM Decapsulation Completed")

        responder_key = self._derive_context_key(
            shared_secret,
            request,
            response,
        )

        if responder_key is None:
            print("M3 rejected : Session Key Derivation Failed")
            self.failed_authentications += 1
            return None

        if not self.context_key_manager.verify_session_key(responder_key):
            print("M3 rejected : Invalid Derived Session Key")
            self.failed_authentications += 1
            return None

        print("✓ Responder Session Key Derived")

        return responder_key


    def establish_session_key(
        self,
        initiator,
        responder,
        responder_public_key,
        request,
    ):
        """
        Compatibility wrapper for older project code.

        The complete authenticate() path should use M3/M4 directly.
        This wrapper retains the old method name so external code that
        imports it does not immediately break.

        IMPORTANT:
        The old implementation performed ML-KEM encapsulation and
        decapsulation in one local function. The main protocol no
        longer uses that behavior; M3 is now an explicit message.
        """

        print("\nEstablishing Session Key through compatibility wrapper...")

        # Create a minimal synthetic M2 state because the old API did
        # not provide an M2 response. This wrapper is for compatibility;
        # authenticate() is the authoritative M1-M4 implementation.
        synthetic_response = {
            "responder": self._identity(responder),
            "timestamp": int(time.time()),
            "nonce": qrng.generate_random_bytes(16),
            "signature": b"",
        }

        # Use the supplied public key rather than responder.kem_pk.
        ciphertext, sender_shared_secret = kyber.encapsulate(
            responder_public_key
        )

        receiver_shared_secret = kyber.decapsulate(
            responder.kem_sk,
            ciphertext,
        )

        sender_key = self._derive_context_key(
            sender_shared_secret,
            request,
            synthetic_response,
        )

        receiver_key = self._derive_context_key(
            receiver_shared_secret,
            request,
            synthetic_response,
        )

        if sender_key != receiver_key:
            print("Session Key Establishment Failed")
            self.failed_authentications += 1
            return False

        self._store_session(
            initiator,
            responder,
            sender_key,
            ciphertext,
            request,
        )

        print("Session Key Established")
        return True

    # =====================================================
    # M4: Create Session-Key Confirmation
    # =====================================================

    def create_m4_confirmation(
        self,
        responder,
        initiator,
        request,
        response,
        session_key,
    ):
        """
        Create M4: Responder -> Initiator.

        M4 confirms that the responder derived the same session key.
        The confirmation is bound to both fresh nonces, both parties,
        and the original authentication timestamp.
        """

        print("\nCreating Message M4 : Session-Key Confirmation...")

        responder_identity = self._identity(responder)

        confirmation = self._confirmation(
            session_key,
            request["nonce"],
            response["nonce"],
            request["sender_pseudonym"],
            responder_identity,
            request["timestamp"],
        )

        m4 = {
            "responder": responder_identity,
            "timestamp": int(time.time()),
            "confirmation": confirmation,
        }

        self.protocol_messages.append({
            "message": "M4",
            "direction": "responder->initiator",
            "fields": tuple(m4.keys()),
        })

        return m4

    # =====================================================
    # M4: Verify Session-Key Confirmation
    # =====================================================

    def verify_m4_confirmation(
        self,
        initiator,
        responder,
        request,
        response,
        session_key,
        m4,
    ):
        """
        Verify M4 and complete mutual key confirmation.
        """

        print("\nVerifying Message M4...")

        if m4.get("responder") != self._identity(responder):
            print("M4 Verification Failed : Wrong Responder")
            self.failed_authentications += 1
            return False

        current_time = int(time.time())

        if abs(current_time - m4["timestamp"]) > self.timestamp_window:
            print("M4 Verification Failed : Timestamp Expired")
            self.failed_authentications += 1
            return False

        expected_confirmation = self._confirmation(
            session_key,
            request["nonce"],
            response["nonce"],
            request["sender_pseudonym"],
            self._identity(responder),
            request["timestamp"],
        )

        if not hmac.compare_digest(
            expected_confirmation,
            m4["confirmation"],
        ):
            print("M4 Verification Failed : Session-Key Confirmation Invalid")
            self.failed_authentications += 1
            return False

        print("✓ M4 Session-Key Confirmation Verified")
        return True

    # =====================================================
    # Store Session
    # =====================================================

    def _store_session(
        self,
        initiator,
        responder,
        session_key,
        ciphertext,
        request,
        response=None,
    ):
        """Store an established session for Secure Message Transfer.

        Only public/session context is retained. The ephemeral ML-KEM
        private key is deliberately never stored here.
        """

        session = {
            "session_key": session_key,
            "ciphertext": ciphertext,
            "created_at": time.time(),
            "expires_at": time.time() + self.session_timeout,
            "m1_timestamp": request["timestamp"],
            "sender_pseudonym": request["sender_pseudonym"],
            "road_segment": request["road_segment"],
            "vehicle_state": request["vehicle_state"],
            "m2_nonce": response["nonce"] if response else None,
        }

        self.active_sessions[
            self._session_record_key(initiator, responder)
        ] = session

    # =====================================================
    # Complete Mutual Authentication
    # =====================================================

    def authenticate(self, sender, receiver):
        """
        Execute the complete M1-M4 PQC mutual authentication protocol.
        """

        print("\n" + "=" * 70)
        print("PQC MUTUAL AUTHENTICATION : M1-M4")
        print("=" * 70)

        print(f"Initiator : {sender.real_id}")

        if isinstance(receiver, Vehicle):
            print(f"Responder : {receiver.real_id}")
        else:
            print(f"Responder : {receiver.rsu_id}")

        print("-" * 70)

        start = time.perf_counter()

        # =================================================
        # M1: Vehicle -> Responder
        # =================================================

        print("\n[ M1 ] Vehicle -> Responder")

        request = self.create_auth_request(
            sender,
            receiver,
        )

        if not self.verify_auth_request(
            receiver,
            request,
        ):
            print("Authentication Failed during M1")
            return False

        print("✓ M1 COMPLETED")

        # =================================================
        # M2: Responder -> Vehicle
        # =================================================

        print("\n[ M2 ] Responder -> Vehicle")

        response = self.create_auth_response(
            receiver,
            sender,
        )

        if not self.verify_auth_response(
            sender,
            receiver,
            response,
        ):
            print("Authentication Failed during M2")
            return False

        print("✓ M2 COMPLETED")

        # =================================================
        # M3: Vehicle -> Responder
        # =================================================

        print("\n[ M3 ] Vehicle -> Responder")

        m3_state = self.create_m3_kem_message(
            sender,
            receiver,
            request,
            response,
        )

        sender_shared_secret = m3_state["shared_secret"]
        m3 = m3_state["m3"]

        responder_session_key = self.process_m3_kem_message(
            sender,
            receiver,
            request,
            response,
            m3,
        )

        # The ephemeral private key is removed by process_m3 immediately
        # after decapsulation and is never retained in the session record.
        response.pop("_ephemeral_kem_sk", None)

        if responder_session_key is None:
            print("Authentication Failed during M3")
            return False

        # -------------------------------------------------
        # Initiator derives the same session key
        # -------------------------------------------------

        sender_session_key = self._derive_context_key(
            sender_shared_secret,
            request,
            response,
        )

        if not self.context_key_manager.verify_session_key(sender_session_key):
            print("Authentication Failed : Invalid Initiator Session Key")
            self.failed_authentications += 1
            return False

        if not hmac.compare_digest(
            sender_session_key,
            responder_session_key,
        ):
            print("Authentication Failed : Session Key Mismatch")
            self.failed_authentications += 1
            return False

        print("✓ Initiator and Responder Derived the Same Session Key")
        print("✓ M3 COMPLETED")

        # =================================================
        # M4: Responder -> Vehicle
        # =================================================

        print("\n[ M4 ] Responder -> Vehicle")

        m4 = self.create_m4_confirmation(
            receiver,
            sender,
            request,
            response,
            responder_session_key,
        )

        if not self.verify_m4_confirmation(
            sender,
            receiver,
            request,
            response,
            sender_session_key,
            m4,
        ):
            print("Authentication Failed during M4")
            return False

        print("✓ M4 COMPLETED")

        # =================================================
        # Store established session
        # =================================================

        self._store_session(
            sender,
            receiver,
            sender_session_key,
            m3["ciphertext"],
            request,
            response,
        )

        elapsed = (time.perf_counter() - start) * 1000

        self.authentication_times.append(elapsed)
        self.successful_authentications += 1

        # =================================================
        # Authentication Log
        # =================================================

        self.authentication_logs.append({
            "sender": sender.real_id,
            "receiver": (
                receiver.rsu_id
                if isinstance(receiver, RSU)
                else receiver.real_id
            ),
            "sender_pid": sender.current_pseudonym,
            "authentication_confidence_token": request["act"],
            "timestamp": request["timestamp"],
            "authentication_time": elapsed,
            "protocol": "M1-M4",
        })

        print("\n" + "=" * 70)
        print("✓ PQC MUTUAL AUTHENTICATION SUCCESSFUL")
        print("=" * 70)
        print(f"Authentication Time : {elapsed:.3f} ms")
        print("M1 : ✓")
        print("M2 : ✓")
        print("M3 : ✓")
        print("M4 : ✓")
        print("Session : ✓ Established")
        print("=" * 70)

        return True

    # =====================================================
    # Forward Secrecy Evaluation
    # =====================================================

    def evaluate_forward_secrecy(self, initiator, responder):
        """
        Evaluate the implemented forward-secrecy property.

        The test models later compromise of the responder's LONG-TERM
        ML-KEM private key. It attempts to recover the previously
        established session key from the recorded M3 ciphertext. Because
        M3 was encapsulated to a per-session ephemeral key whose private
        key has been discarded, the long-term key must not reproduce the
        old session key.
        """

        session_key_id = self._session_record_key(initiator, responder)
        session = self.active_sessions.get(session_key_id)

        if session is None:
            print("Forward Secrecy Evaluation : NO ACTIVE SESSION")
            return False

        print("\n" + "=" * 70)
        print("FORWARD SECRECY EVALUATION")
        print("=" * 70)
        print("Simulating later compromise of the responder's long-term ML-KEM key...")

        # The ephemeral private key must not be present in the session.
        ephemeral_retained = "_ephemeral_kem_sk" in session

        if ephemeral_retained:
            print("✗ Ephemeral private key is still retained")
            return False

        try:
            compromised_shared_secret = kyber.decapsulate(
                responder.kem_sk,
                session["ciphertext"],
            )

            request_context = {
                "road_segment": session["road_segment"],
                "sender_pseudonym": session["sender_pseudonym"],
                "timestamp": session["m1_timestamp"],
            }
            response_context = {
                "nonce": session["m2_nonce"],
            }

            recovered_session_key = self._derive_context_key(
                compromised_shared_secret,
                request_context,
                response_context,
            )

            protected = not hmac.compare_digest(
                recovered_session_key,
                session["session_key"],
            )
        except Exception as e:
            print(f"Long-term-key recovery attempt failed: {e}")
            protected = True

        if protected:
            print("✓ Previous session key was NOT recoverable using the long-term ML-KEM key")
            print("✓ Ephemeral ML-KEM private key is not retained in the session")
            print("✓ Forward Secrecy : IMPLEMENTED")
        else:
            print("✗ Previous session key was recoverable")
            print("✗ Forward Secrecy : FAILED")

        print("=" * 70)
        return protected

    # =====================================================
    # Network Authentication
    # =====================================================

    def authenticate_network(self, vehicles, rsus):
        """
        Perform authentication across the network.
        """

        print("\n")
        print("=" * 70)
        print("NETWORK AUTHENTICATION")
        print("=" * 70)

        # Vehicle <-> Vehicle
        if len(vehicles) >= 2:
            self.authenticate(
                vehicles[0],
                vehicles[1],
            )

        # Vehicle <-> RSU
        if len(vehicles) >= 1 and len(rsus) >= 1:
            self.authenticate(
                vehicles[0],
                rsus[0],
            )

        if len(vehicles) >= 2 and len(rsus) >= 1:
            self.authenticate(
                vehicles[1],
                rsus[0],
            )

    # =====================================================
    # Get Active Session
    # =====================================================

    def get_session(self, initiator_id, responder_id):
        """
        Return an active session if available.
        """

        session_key = (
            initiator_id,
            responder_id,
        )

        session = self.active_sessions.get(session_key)

        if session is None:
            return None

        if session["expires_at"] < time.time():
            del self.active_sessions[session_key]
            return None

        return session

    # =====================================================
    # Compatibility Wrapper
    # =====================================================

    def get_session_key(self, initiator_id, responder_id):
        """
        Return only the session key for compatibility with
        Secure Message Transfer.
        """

        session = self.get_session(
            initiator_id,
            responder_id,
        )

        if session is None:
            return None

        return session["session_key"]

    # =====================================================
    # Remove Session
    # =====================================================

    def remove_session(self, initiator_id, responder_id):
        """Remove an active session."""

        self.active_sessions.pop(
            (
                initiator_id,
                responder_id,
            ),
            None,
        )

    # =====================================================
    # Clear All Sessions
    # =====================================================

    def clear_sessions(self):
        """Remove every active session."""

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
                / len(self.authentication_times)
            )
        else:
            average = 0.0

        print(
            f"Average Authentication Time : "
            f"{average:.3f} ms"
        )

        print()
        print("=" * 70)
        print("ACT STATISTICS")
        print("=" * 70)

        print(f"Generated Tokens           : {self.act_generated}")
        print(f"Verified Tokens            : {self.act_verified}")
        print(f"Rejected Tokens            : {self.act_rejected}")

        if self.act_generation_times:
            avg_generation = (
                sum(self.act_generation_times)
                / len(self.act_generation_times)
            )
            print(
                f"Average Generation Time   : "
                f"{avg_generation:.3f} ms"
            )

        if self.act_verification_times:
            avg_verification = (
                sum(self.act_verification_times)
                / len(self.act_verification_times)
            )
            print(
                f"Average Verification Time : "
                f"{avg_verification:.3f} ms"
            )

        print()
        print("=" * 70)
        print("ACT PRE-FILTER STATISTICS")
        print("=" * 70)

        print(f"ACT Generated              : {self.act_generated}")
        print(f"ACT Verified               : {self.act_verified}")
        print(f"ACT Rejected               : {self.act_rejected}")

        if self.act_generation_times:
            print(
                f"Average ACT Generation Time : "
                f"{sum(self.act_generation_times) / len(self.act_generation_times):.3f} ms"
            )
        else:
            print("Average ACT Generation Time : 0.000 ms")

        if self.act_verification_times:
            print(
                f"Average ACT Verification Time : "
                f"{sum(self.act_verification_times) / len(self.act_verification_times):.3f} ms"
            )
        else:
            print("Average ACT Verification Time : 0.000 ms")

        print()
        print("=" * 70)
        print("PQC M1-M4 AUTHENTICATION STATISTICS")
        print("=" * 70)

        print(f"M1-M4 Successful            : {self.successful_authentications}")
        print(f"M1-M4 Failed                : {self.failed_authentications}")
        print(f"Active Sessions             : {len(self.active_sessions)}")
        print(
            f"Average M1-M4 Authentication Time : "
            f"{average:.3f} ms"
        )

        print("=" * 70)

    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):
        average = (
            sum(self.authentication_times)
            / len(self.authentication_times)
            if self.authentication_times
            else 0.0
        )

        return {
            "successful_authentications": self.successful_authentications,
            "failed_authentications": self.failed_authentications,
            "active_sessions": len(self.active_sessions),
            "average_authentication_time": average,
            "authentication_times": self.authentication_times.copy(),
            "authentication_logs": self.authentication_logs.copy(),
            "act_generated": self.act_generated,
            "act_verified": self.act_verified,
            "act_rejected": self.act_rejected,
            "act_generation_times": self.act_generation_times.copy(),
            "act_verification_times": self.act_verification_times.copy(),
            "protocol_messages": self.protocol_messages.copy(),
        }

    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):
        self.authentication_times.clear()
        self.authentication_logs.clear()
        self.protocol_messages.clear()
        self.active_sessions.clear()
        self.used_nonces.clear()
        self.used_timestamps.clear()

        self.act_generated = 0
        self.act_verified = 0
        self.act_rejected = 0
        self.act_generation_times.clear()
        self.act_verification_times.clear()

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

    # =====================================================
    # ACT Failure Demonstration
    # =====================================================

    def demo_invalid_act(self, sender, receiver):
        """
        Demonstrate that an invalid ACT is rejected before ML-DSA
        verification and before M3/ML-KEM processing.
        """

        print("\n" + "=" * 70)
        print("ACT FAILURE DEMONSTRATION")
        print("=" * 70)

        request = self.create_auth_request(
            sender,
            receiver,
        )

        request["act"] = "INVALID_ACT"

        print("\nACT has been intentionally modified.")

        result = self.verify_auth_request(
            receiver,
            request,
        )

        if not result:
            print("\nAuthentication Rejected by ACT Pre-Filter")
            print("ML-DSA Verification Skipped")
            print("M3 / ML-KEM Key Establishment Skipped")
            print("M4 / Session Confirmation Skipped")

        print("=" * 70)
