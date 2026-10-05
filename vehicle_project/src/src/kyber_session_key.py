"""
=========================================================
Kyber Session Key Manager
---------------------------------------------------------
Provides ML-KEM (Kyber) based session key establishment
for the PQC-VANET Protocol.

Supports

• Vehicle ↔ Vehicle
• Vehicle ↔ RSU
• Session Key Generation
• Session Key Management

Author : Meeth Amin
=========================================================
"""

import time

from crypto import kyber

from models import Vehicle
from models import RSU


class KyberSessionKey:

    """
    ML-KEM Session Key Manager
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(self):

        # ===============================================
        # Active Session Keys
        # ===============================================

        self.session_keys = {}

        # ===============================================
        # Statistics
        # ===============================================

        self.key_generation_times = []

        self.successful_sessions = 0

        self.failed_sessions = 0

        # ===============================================
        # Logs
        # ===============================================

        self.session_logs = []

        print("\nKyber Session Key Manager Initialized")
            # =====================================================
    # Establish Session Key
    # =====================================================

    def establish_session(
        self,
        initiator,
        responder
    ):
        """
        Establish an ML-KEM session key between two nodes.

        Supports:
            Vehicle ↔ Vehicle
            Vehicle ↔ RSU
        """

        print("\nEstablishing Kyber Session Key...")

        start = time.perf_counter()

        # -------------------------------------------------
        # ML-KEM Encapsulation
        # -------------------------------------------------

        ciphertext, shared_secret_sender = (

            kyber.encapsulate(

                responder.kem_pk

            )

        )

        # -------------------------------------------------
        # ML-KEM Decapsulation
        # -------------------------------------------------

        shared_secret_receiver = (

            kyber.decapsulate(

                responder.kem_sk,

                ciphertext

            )

        )

        # -------------------------------------------------
        # Session Context
        # -------------------------------------------------

        responder_identity = (

            responder.real_id

            if isinstance(responder, Vehicle)

            else responder.rsu_id

        )

        context = (

            initiator.real_id +

            responder_identity

        )

        # -------------------------------------------------
        # Derive Session Keys
        # -------------------------------------------------

        sender_session_key = (

            kyber.derive_session_key(

                shared_secret_sender,

                context

            )

        )

        receiver_session_key = (

            kyber.derive_session_key(

                shared_secret_receiver,

                context

            )

        )

        # -------------------------------------------------
        # Verify Session Keys
        # -------------------------------------------------

        if sender_session_key != receiver_session_key:

            self.failed_sessions += 1

            print("Session Key Generation Failed")

            return None

        # -------------------------------------------------
        # Store Session
        # -------------------------------------------------

        session = {

            "initiator":

                initiator.real_id,

            "responder":

                responder_identity,

            "session_key":

                sender_session_key,

            "ciphertext":

                ciphertext,

            "created_at":

                time.time()

        }

        self.session_keys[

            (

                initiator.real_id,

                responder_identity

            )

        ] = session

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.key_generation_times.append(

            elapsed

        )

        self.successful_sessions += 1

        self.session_logs.append({

            "initiator":

                initiator.real_id,

            "responder":

                responder_identity,

            "generation_time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print("Session Key Established")

        print(

            f"Generation Time : "

            f"{elapsed:.3f} ms"

        )

        return sender_session_key
            # =====================================================
    # Get Session Key
    # =====================================================

    def get_session_key(
        self,
        initiator_id,
        responder_id
    ):
        """
        Return an existing session key.
        """

        session = self.session_keys.get(

            (initiator_id, responder_id),

            None

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

        self.session_keys.pop(

            (initiator_id, responder_id),

            None

        )


    # =====================================================
    # Clear All Sessions
    # =====================================================

    def clear_sessions(self):
        """
        Remove all active session keys.
        """

        self.session_keys.clear()

        print("All Session Keys Cleared")


    # =====================================================
    # Display Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)

        print("KYBER SESSION KEY STATISTICS")

        print("=" * 70)

        print(

            f"Successful Sessions : "

            f"{self.successful_sessions}"

        )

        print(

            f"Failed Sessions     : "

            f"{self.failed_sessions}"

        )

        print(

            f"Active Sessions     : "

            f"{len(self.session_keys)}"

        )

        if self.key_generation_times:

            average = (

                sum(self.key_generation_times)

                /

                len(self.key_generation_times)

            )

            print(

                f"Average Generation Time : "

                f"{average:.3f} ms"

            )

        else:

            print(

                "Average Generation Time : 0.000 ms"

            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        if self.key_generation_times:

            average = (

                sum(self.key_generation_times)

                /

                len(self.key_generation_times)

            )

        else:

            average = 0.0

        return {

            "successful_sessions":

                self.successful_sessions,

            "failed_sessions":

                self.failed_sessions,

            "active_sessions":

                len(self.session_keys),

            "average_generation_time":

                average,

            "generation_times":

                self.key_generation_times.copy(),

            "session_logs":

                self.session_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.session_keys.clear()

        self.key_generation_times.clear()

        self.session_logs.clear()

        self.successful_sessions = 0

        self.failed_sessions = 0

        print("Kyber Session Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"KyberSessionKey("

            f"Sessions={len(self.session_keys)}, "

            f"Success={self.successful_sessions}, "

            f"Failed={self.failed_sessions})"

        )