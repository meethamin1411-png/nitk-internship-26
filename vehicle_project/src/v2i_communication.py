"""
=========================================================
Vehicle-to-Infrastructure Communication Manager
---------------------------------------------------------
Provides secure Vehicle-to-RSU communication
for the PQC-VANET Protocol.

Supports

• Vehicle ↔ RSU Authentication
• Secure Messaging
• Infrastructure Communication

Author : Meeth Amin
=========================================================
"""

import time

from models import Vehicle
from models import RSU

from mutual_authentication import MutualAuthentication

from secure_messege_transfer import SecureMessageTransfer


class V2ICommunication:

    """
    Secure Vehicle-to-Infrastructure Communication Manager
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        authentication_manager: MutualAuthentication,
        secure_transfer: SecureMessageTransfer
    ):

        self.authentication = authentication_manager

        self.secure_transfer = secure_transfer

        # ===============================================
        # Statistics
        # ===============================================

        self.total_messages = 0

        self.successful_messages = 0

        self.failed_messages = 0

        self.communication_times = []

        # ===============================================
        # Logs
        # ===============================================

        self.communication_logs = []

        print("\nV2I Communication Manager Initialized")
            # =====================================================
    # Send Secure V2I Message
    # =====================================================

    def send_message(
        self,
        vehicle: Vehicle,
        rsu: RSU,
        message
    ):
        """
        Secure Vehicle-to-Infrastructure communication.
        """

        print("\n" + "=" * 70)
        print("VEHICLE TO INFRASTRUCTURE COMMUNICATION")
        print("=" * 70)

        start = time.perf_counter()

        # -------------------------------------------------
        # Check Authentication
        # -------------------------------------------------

        session = self.authentication.get_session(

            vehicle.real_id,

            rsu.rsu_id

        )

        if session is None:

            print("No Active Session")

            print("Starting Mutual Authentication...")

            status = self.authentication.authenticate(

                vehicle,

                rsu

            )

            if not status:

                self.failed_messages += 1

                print("Authentication Failed")

                return None

        # -------------------------------------------------
        # Encrypt Message
        # -------------------------------------------------

        packet = self.secure_transfer.secure_send(

            vehicle,

            rsu,

            message

        )

        if packet is None:

            self.failed_messages += 1

            return None

        # -------------------------------------------------
        # RSU Decrypts
        # -------------------------------------------------

        plaintext = self.secure_transfer.secure_receive(

            rsu,

            packet

        )

        if plaintext is None:

            self.failed_messages += 1

            return None

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        self.total_messages += 1

        self.successful_messages += 1

        self.communication_times.append(

            elapsed

        )

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.communication_logs.append({

            "vehicle":

                vehicle.real_id,

            "rsu":

                rsu.rsu_id,

            "message":

                message,

            "communication_time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print("\nVehicle-to-Infrastructure Communication Successful")

        print(

            f"Communication Time : "

            f"{elapsed:.3f} ms"

        )

        return plaintext
            # =====================================================
    # Broadcast Message to Multiple RSUs
    # =====================================================

    def broadcast_to_rsus(
        self,
        vehicle: Vehicle,
        rsus,
        message
    ):
        """
        Securely broadcast a message from one vehicle
        to multiple RSUs.
        """

        print("\n" + "=" * 70)
        print("V2I BROADCAST")
        print("=" * 70)

        delivered = []

        failed = []

        for rsu in rsus:

            print(

                f"\nSending Message to {rsu.rsu_id}"

            )

            plaintext = self.send_message(

                vehicle,

                rsu,

                message

            )

            if plaintext is None:

                failed.append(

                    rsu.rsu_id

                )

            else:

                delivered.append(

                    rsu.rsu_id

                )

        print("\nBroadcast Completed")

        print(

            f"Delivered : {len(delivered)}"

        )

        print(

            f"Failed    : {len(failed)}"

        )

        return {

            "delivered":

                delivered,

            "failed":

                failed

        }


    # =====================================================
    # Check Vehicle-RSU Connectivity
    # =====================================================

    def check_connectivity(
        self,
        vehicle: Vehicle,
        rsu: RSU
    ):
        """
        Determine whether the vehicle has an
        authenticated session with the RSU.
        """

        session = self.authentication.get_session(

            vehicle.real_id,

            rsu.rsu_id

        )

        return session is not None


    # =====================================================
    # Display Communication Logs
    # =====================================================

    def show_logs(self):

        print("\n" + "=" * 70)

        print("V2I COMMUNICATION LOGS")

        print("=" * 70)

        if not self.communication_logs:

            print("No Communication Recorded")

            return

        for log in self.communication_logs:

            print(log)

        print("=" * 70)
            # =====================================================
    # Display Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)
        print("V2I COMMUNICATION STATISTICS")
        print("=" * 70)

        print(
            f"Total Messages        : "
            f"{self.total_messages}"
        )

        print(
            f"Successful Messages   : "
            f"{self.successful_messages}"
        )

        print(
            f"Failed Messages       : "
            f"{self.failed_messages}"
        )

        if self.communication_times:

            average = (

                sum(self.communication_times)

                /

                len(self.communication_times)

            )

            print(

                f"Average Communication Time : "

                f"{average:.3f} ms"

            )

        else:

            print(

                "Average Communication Time : 0.000 ms"

            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        average = (

            sum(self.communication_times)

            /

            len(self.communication_times)

            if self.communication_times

            else 0.0

        )

        return {

            "total_messages":

                self.total_messages,

            "successful_messages":

                self.successful_messages,

            "failed_messages":

                self.failed_messages,

            "average_communication_time":

                average,

            "communication_times":

                self.communication_times.copy(),

            "communication_logs":

                self.communication_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.total_messages = 0

        self.successful_messages = 0

        self.failed_messages = 0

        self.communication_times.clear()

        self.communication_logs.clear()

        print("V2I Communication Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"V2ICommunication("

            f"Messages={self.total_messages}, "

            f"Success={self.successful_messages}, "

            f"Failed={self.failed_messages})"

        )