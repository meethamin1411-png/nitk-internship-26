"""
=======================================================================
LIGHTWEIGHT REVOCATION PROTOCOL
-----------------------------------------------------------------------
Research Module:
Lightweight Revocation Protocol for
Post-Quantum Certificateless VANET

Author : Meeth Amin
=======================================================================
"""

import time
import hashlib
from datetime import datetime

from crypto import qrng
from crypto import dilithium


from context_aware_session_key import ContextAwareSessionKey



class LightweightRevocation:
    """
    Lightweight Revocation Protocol

    Features
    --------
    • Revocation Identifier (RID)
    • Secure Revocation Message
    • ML-DSA Signature
    • Revocation Verification
    • Vehicle Revocation
    • Session Key Destruction
    • Adaptive PID Invalidation
    • Secure Re-registration
    """

    # ==========================================================
    # Constructor
    # ==========================================================

    def __init__(self, trusted_authority):

        print("\n" + "=" * 70)
        print("INITIALIZING LIGHTWEIGHT REVOCATION PROTOCOL")
        print("=" * 70)

        self.ta = trusted_authority

        self.context_key_manager = ContextAwareSessionKey()

        # ------------------------------------------------------
        # RID Database
        # ------------------------------------------------------

        self.rid_database = {}

        # ------------------------------------------------------
        # Revocation Messages
        # ------------------------------------------------------

        self.revocation_messages = []

        # ------------------------------------------------------
        # Statistics
        # ------------------------------------------------------

        self.total_revocations = 0
        self.successful_verifications = 0
        self.failed_verifications = 0

        self.execution_times = []

        print("✓ Revocation Manager Ready")

    # ==========================================================
    # Generate Revocation Identifier
    # ==========================================================

    def generate_rid(self, vehicle):

        print("\n" + "=" * 70)
        print("GENERATING REVOCATION IDENTIFIER")
        print("=" * 70)

        start = time.perf_counter()

        timestamp = str(int(time.time() * 1000))

        random_seed = qrng.generate_random_hex(16)

        rid = hashlib.sha3_256(

            (
                vehicle.real_id +
                vehicle.current_pseudonym +
                timestamp +
                random_seed
            ).encode()

        ).hexdigest()

        self.rid_database[rid] = {

            "vehicle_id": vehicle.real_id,

            "pseudonym": vehicle.current_pseudonym,

            "timestamp": timestamp,

            "status": "ACTIVE"

        }

        elapsed = (time.perf_counter() - start) * 1000

        self.execution_times.append(elapsed)

        print("Vehicle ID :", vehicle.real_id)

        print("Adaptive PID :", vehicle.current_pseudonym)

        print("✓ RID Generated")

        print(f"Generation Time : {elapsed:.3f} ms")

        return rid

    # ==========================================================
    # Create Revocation Message
    # ==========================================================

    def create_revocation_message(

            self,

            vehicle,

            reason,

            severity,

            ta_private_key

    ):

        print("\n" + "=" * 70)

        print("CREATING REVOCATION MESSAGE")

        print("=" * 70)

        rid = self.generate_rid(vehicle)

        timestamp = str(int(time.time()))

        message = {

            "rid": rid,

            "vehicle_id": vehicle.real_id,

            "pseudonym": vehicle.current_pseudonym,

            "reason": reason,

            "severity": severity,

            "timestamp": timestamp

        }

        message_bytes = str(message).encode()

        signature = dilithium.sign_message(

            ta_private_key,

            message_bytes

        )

        message["signature"] = signature

        self.revocation_messages.append(message)

        print("✓ Revocation Message Created")

        print("✓ ML-DSA Signature Attached")

        return message

    # ==========================================================
    # Verify Revocation Message
    # ==========================================================

    def verify_revocation_message(

            self,

            message,

            ta_public_key

    ):

        print("\n" + "=" * 70)

        print("VERIFYING REVOCATION MESSAGE")

        print("=" * 70)

        signature = message["signature"]

        unsigned = message.copy()

        del unsigned["signature"]

        status = dilithium.verify_signature(

            ta_public_key,

            str(unsigned).encode(),

            signature

        )

        if status:

            self.successful_verifications += 1

            print("✓ Revocation Signature Verified")

        else:

            self.failed_verifications += 1

            print("✗ Invalid Revocation Signature")

        return status
            # ==========================================================
    # Revoke Vehicle
    # ==========================================================

    def revoke_vehicle(

            self,

            vehicle,

            reason="Malicious Behaviour",

            severity="HIGH"

    ):

        """
        Complete lightweight revocation procedure.
        """

        print("\n" + "=" * 70)
        print("LIGHTWEIGHT VEHICLE REVOCATION")
        print("=" * 70)

        start = time.perf_counter()

        # ------------------------------------------------------
        # Already Revoked?
        # ------------------------------------------------------

        if self.ta.is_revoked(vehicle.real_id):

            print("Vehicle Already Revoked")

            return False

        # ------------------------------------------------------
        # Create Revocation Message
        # ------------------------------------------------------

        message = self.create_revocation_message(

            vehicle,

            reason,

            severity,

            self.ta.ta_sk

        )

        # ------------------------------------------------------
        # Verify TA Signature
        # ------------------------------------------------------

        status = self.verify_revocation_message(

            message,

            self.ta.ta_pk

        )

        if not status:

            print("Revocation Aborted")

            return False

        # ------------------------------------------------------
        # Trusted Authority Revocation
        # ------------------------------------------------------

        self.ta.revoke_vehicle(

            vehicle.real_id

        )

        # ------------------------------------------------------
        # Vehicle Status
        # ------------------------------------------------------

        vehicle.status = "REVOKED"

        vehicle.revoked = True

        # ------------------------------------------------------
        # Destroy Session Keys
        # ------------------------------------------------------

        print("\nDestroying Session Keys...")

        vehicle.reset_session_keys()

        # ------------------------------------------------------
        # Remove Current PID
        # ------------------------------------------------------

        print("Invalidating Adaptive PID...")

        vehicle.previous_pseudonym = vehicle.current_pseudonym

        vehicle.current_pseudonym = None

        # ------------------------------------------------------
        # Statistics
        # ------------------------------------------------------

        elapsed = (

            time.perf_counter() -

            start

        ) * 1000

        self.total_revocations += 1

        self.execution_times.append(elapsed)

        print()

        print("✓ Vehicle Successfully Revoked")

        print(f"Revocation Time : {elapsed:.3f} ms")

        return True

    # ==========================================================
    # Authentication Permission
    # ==========================================================

    def can_authenticate(

            self,

            vehicle

    ):

        """
        Returns whether the vehicle is allowed
        to participate in authentication.
        """

        if vehicle.revoked:

            return False

        if self.ta.is_revoked(

                vehicle.real_id

        ):

            return False

        if vehicle.current_pseudonym is None:

            return False

        return True

    # ==========================================================
    # Get Revocation Status
    # ==========================================================

    def get_revocation_status(

            self,

            vehicle

    ):

        """
        Return current revocation status.
        """

        return {

            "vehicle_id": vehicle.real_id,

            "status": vehicle.status,

            "revoked": vehicle.revoked,

            "registered": vehicle.registration_status,

            "current_pid": vehicle.current_pseudonym,

            "session_keys": len(vehicle.session_keys),

            "ta_status": self.ta.get_vehicle_status(

                vehicle.real_id

            )

        }

    # ==========================================================
    # Print Revocation Status
    # ==========================================================

    def show_revocation_status(

            self,

            vehicle

    ):

        info = self.get_revocation_status(

            vehicle

        )

        print("\n" + "=" * 70)

        print("REVOCATION STATUS")

        print("=" * 70)

        print(f"Vehicle ID      : {info['vehicle_id']}")

        print(f"Vehicle Status  : {info['status']}")

        print(f"Revoked         : {info['revoked']}")

        print(f"Registered      : {info['registered']}")

        print(f"Current PID     : {info['current_pid']}")

        print(f"Session Keys    : {info['session_keys']}")

        print(f"TA Status       : {info['ta_status']}")

        print("=" * 70)
            # ==========================================================
    # Cooldown Before Rejoining Network
    # ==========================================================

    def cooldown(self, seconds=5):

        print("\n" + "=" * 70)
        print("SECURITY COOLDOWN")
        print("=" * 70)

        for remaining in range(seconds, 0, -1):

            print(f"Rejoining Network In : {remaining} sec")

            time.sleep(1)

        print("✓ Cooldown Completed")

    # ==========================================================
    # Generate Fresh Identity
    # ==========================================================

    def generate_new_identity(self, vehicle):

        """
        Generate a completely fresh cryptographic identity.
        """

        print("\n" + "=" * 70)
        print("GENERATING NEW VEHICLE IDENTITY")
        print("=" * 70)

        # -----------------------------------------
        # Fresh PQC Keys
        # -----------------------------------------

        vehicle.initialize_crypto()

        # -----------------------------------------
        # Fresh Secret Value
        # -----------------------------------------

        vehicle.generate_secret_value()

        # -----------------------------------------
        # Fresh Partial Keys
        # -----------------------------------------

        self.ta.issue_partial_keys(vehicle)

        self.ta.store_vehicle_keys(vehicle)

        print("✓ Fresh Certificateless Identity Generated")

        return True

    # ==========================================================
    # Generate Fresh Adaptive PID
    # ==========================================================

    def generate_new_pseudonym(self, vehicle):

        print("\n" + "=" * 70)
        print("GENERATING NEW ADAPTIVE PSEUDONYM")
        print("=" * 70)

        new_pid = vehicle.generate_pseudonym()

        self.ta.update_pseudonym(

            vehicle.real_id,

            new_pid

        )

        print("✓ Trusted Authority Updated")

        return new_pid

    # ==========================================================
    # Restore Vehicle
    # ==========================================================

    def restore_vehicle(self, vehicle):

        print("\n" + "=" * 70)
        print("RESTORING VEHICLE")
        print("=" * 70)

        vehicle.status = "ACTIVE"

        vehicle.revoked = False

        print("✓ Vehicle Status Restored")

        return True

    # ==========================================================
    # Secure Re-Registration
    # ==========================================================

    def re_register_vehicle(self, vehicle):

        """
        Complete secure re-registration.
        """

        print("\n" + "=" * 70)
        print("SECURE RE-REGISTRATION")
        print("=" * 70)

        start = time.perf_counter()

        # -----------------------------------------
        # Security Cooldown
        # -----------------------------------------

        self.cooldown()

        # -----------------------------------------
        # Restore Vehicle
        # -----------------------------------------

        self.restore_vehicle(vehicle)

        # -----------------------------------------
        # Fresh PQC Identity
        # -----------------------------------------

        self.generate_new_identity(vehicle)

        # -----------------------------------------
        # Fresh Adaptive PID
        # -----------------------------------------

        self.generate_new_pseudonym(vehicle)

        # -----------------------------------------
        # Remove from TA Revocation List
        # -----------------------------------------

        if vehicle.real_id in self.ta.revocation_list:

            self.ta.revocation_list.remove(

                vehicle.real_id

            )

        if vehicle.real_id in self.ta.vehicle_registry:

            self.ta.vehicle_registry[

                vehicle.real_id

            ]["status"] = "ACTIVE"

            self.ta.vehicle_registry[

                vehicle.real_id

            ]["revoked"] = False

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        print()

        print("✓ Vehicle Successfully Re-Registered")

        print(f"Recovery Time : {elapsed:.3f} ms")

        return True

    # ==========================================================
    # Show RID Database
    # ==========================================================

    def show_rid_database(self):

        print("\n" + "=" * 70)
        print("REVOCATION IDENTIFIER DATABASE")
        print("=" * 70)

        if not self.rid_database:

            print("No Revocation Records")

            print("=" * 70)

            return

        for rid, info in self.rid_database.items():

            print()

            print("RID :", rid)

            print("Vehicle :", info["vehicle_id"])

            print("PID :", info["pseudonym"])

            print("Timestamp :", info["timestamp"])

            print("Status :", info["status"])

        print("\n" + "=" * 70)
            # ==========================================================
    # Performance Statistics
    # ==========================================================

    def show_statistics(self):

        print("\n" + "=" * 70)
        print("LIGHTWEIGHT REVOCATION STATISTICS")
        print("=" * 70)

        avg = 0

        if len(self.execution_times) > 0:

            avg = sum(self.execution_times) / len(self.execution_times)

        print(f"Total Revocations           : {self.total_revocations}")
        print(f"Successful Verifications    : {self.successful_verifications}")
        print(f"Failed Verifications        : {self.failed_verifications}")
        print(f"Generated RIDs              : {len(self.rid_database)}")
        print(f"Stored Revocation Messages  : {len(self.revocation_messages)}")
        print(f"Average Execution Time      : {avg:.3f} ms")

        print("=" * 70)

    # ==========================================================
    # Complete Protocol Report
    # ==========================================================

    def protocol_report(self, vehicle):

        print("\n" + "=" * 70)
        print("LIGHTWEIGHT REVOCATION PROTOCOL REPORT")
        print("=" * 70)

        print(f"Vehicle ID            : {vehicle.real_id}")
        print(f"Vehicle Status        : {vehicle.status}")
        print(f"Current PID           : {vehicle.current_pseudonym}")
        print(f"Registered            : {vehicle.registration_status}")
        print(f"Revoked               : {vehicle.revoked}")
        print(f"Stored Session Keys   : {len(vehicle.session_keys)}")

        ta_status = self.ta.get_vehicle_status(vehicle.real_id)

        print(f"TA Status             : {ta_status}")

        print("=" * 70)

        self.show_statistics()


# ==========================================================
# Demonstration
# ==========================================================

if __name__ == "__main__":

    from models.trusted_authority import TrustedAuthority
    from models.vehicle import Vehicle

    print("\n")
    print("=" * 70)
    print("PQC-VANET LIGHTWEIGHT REVOCATION DEMO")
    print("=" * 70)

    # ------------------------------------------------------
    # Trusted Authority
    # ------------------------------------------------------

    ta = TrustedAuthority()

    # ------------------------------------------------------
    # Vehicle
    # ------------------------------------------------------

    vehicle = Vehicle(

        real_id="VEHICLE001",

        trusted_authority=ta

    )

    # ------------------------------------------------------
    # Registration
    # ------------------------------------------------------

    ta.register_vehicle(vehicle)

    vehicle.register()

    # ------------------------------------------------------
    # PQC Identity
    # ------------------------------------------------------

    vehicle.initialize_crypto()

    vehicle.generate_secret_value()

    ta.issue_partial_keys(vehicle)

    ta.store_vehicle_keys(vehicle)

    # ------------------------------------------------------
    # Initial Adaptive PID
    # ------------------------------------------------------

    vehicle.generate_pseudonym()

    # ------------------------------------------------------
    # Revocation Manager
    # ------------------------------------------------------

    manager = LightweightRevocation(ta)

    # ------------------------------------------------------
    # Revoke Vehicle
    # ------------------------------------------------------

    manager.revoke_vehicle(

        vehicle,

        reason="False Safety Message Injection",

        severity="HIGH"

    )

    manager.show_revocation_status(vehicle)

    print()

    print(
        "Authentication Allowed :",
        manager.can_authenticate(vehicle)
    )

    # ------------------------------------------------------
    # Secure Re-Registration
    # ------------------------------------------------------

    manager.re_register_vehicle(vehicle)

    print()

    print(
        "Authentication Allowed :",
        manager.can_authenticate(vehicle)
    )

    # ------------------------------------------------------
    # Reports
    # ------------------------------------------------------

    manager.show_rid_database()

    manager.protocol_report(vehicle)

    print()

    print("=" * 70)
    print("LIGHTWEIGHT REVOCATION PROTOCOL COMPLETED")
    print("=" * 70)