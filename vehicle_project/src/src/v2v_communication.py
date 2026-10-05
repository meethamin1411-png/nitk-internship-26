"""
=========================================================
Vehicle-to-Vehicle Communication Manager
---------------------------------------------------------
Provides secure V2V communication for the
PQC-VANET Protocol.

Supports

• Mutual Authentication
• Secure Messaging
• Session Management

Author : Meeth Amin
=========================================================
"""

import time

from models import Vehicle

from mutual_authentication import MutualAuthentication

from secure_messege_transfer import SecureMessageTransfer


class V2VCommunication:

    """
    Secure Vehicle-to-Vehicle Communication Manager
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

        print("\nV2V Communication Manager Initialized")
            # =====================================================
    # Send Secure V2V Message
    # =====================================================

    def send_message(
        self,
        sender: Vehicle,
        receiver: Vehicle,
        message
    ):
        """
        Secure Vehicle-to-Vehicle communication.
        """

        print("\n" + "=" * 70)
        print("VEHICLE TO VEHICLE COMMUNICATION")
        print("=" * 70)

        start = time.perf_counter()

        # -------------------------------------------------
        # Check Authentication
        # -------------------------------------------------

        session = self.authentication.get_session(

            sender.real_id,

            receiver.real_id

        )

        if session is None:

            print("No Active Session")

            print("Starting Mutual Authentication...")

            status = self.authentication.authenticate(

                sender,

                receiver

            )

            if not status:

                self.failed_messages += 1

                print("Authentication Failed")

                return None

        # -------------------------------------------------
        # Encrypt Message
        # -------------------------------------------------

        packet = self.secure_transfer.secure_send(

            sender,

            receiver,

            message

        )

        if packet is None:

            self.failed_messages += 1

            return None

        # -------------------------------------------------
        # Receiver Decrypts
        # -------------------------------------------------

        plaintext = self.secure_transfer.secure_receive(

            receiver,

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

            "sender":

                sender.real_id,

            "receiver":

                receiver.real_id,

            "message":

                message,

            "communication_time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print("\nVehicle-to-Vehicle Communication Successful")

        print(

            f"Communication Time : "

            f"{elapsed:.3f} ms"

        )

        return plaintext
            # =====================================================
    # Broadcast Secure Message
    # =====================================================

    def broadcast_message(
        self,
        sender: Vehicle,
        receivers,
        message
    ):
        """
        Securely broadcast a message to multiple vehicles.
        """

        print("\n" + "=" * 70)
        print("SECURE V2V BROADCAST")
        print("=" * 70)

        delivered = []

        failed = []

        for receiver in receivers:

            # Ignore self
            if receiver.real_id == sender.real_id:

                continue

            print(
                f"\nBroadcasting to {receiver.real_id}"
            )

            plaintext = self.send_message(

                sender,

                receiver,

                message

            )

            if plaintext is None:

                failed.append(

                    receiver.real_id

                )

            else:

                delivered.append(

                    receiver.real_id

                )

        print("\nBroadcast Completed")

        print(
            f"Delivered : {len(delivered)}"
        )

        print(
            f"Failed    : {len(failed)}"
        )

        return {

            "delivered": delivered,

            "failed": failed

        }


    # =====================================================
    # Check Connectivity
    # =====================================================

    def check_connectivity(
        self,
        vehicle1: Vehicle,
        vehicle2: Vehicle
    ):
        """
        Determine whether two vehicles have
        an authenticated session.
        """

        session = self.authentication.get_session(

            vehicle1.real_id,

            vehicle2.real_id

        )

        return session is not None


    # =====================================================
    # Display Communication Logs
    # =====================================================

    def show_logs(self):

        print("\n" + "=" * 70)

        print("V2V COMMUNICATION LOGS")

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
        print("V2V COMMUNICATION STATISTICS")
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

        print("V2V Communication Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"V2VCommunication("

            f"Messages={self.total_messages}, "

            f"Success={self.successful_messages}, "

            f"Failed={self.failed_messages})"

        )