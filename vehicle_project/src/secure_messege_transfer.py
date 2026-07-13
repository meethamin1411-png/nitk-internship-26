"""
=========================================================
Secure Message Transfer Manager
---------------------------------------------------------
Provides authenticated secure communication for
the PQC-VANET Protocol.

Supports

• Vehicle ↔ Vehicle
• Vehicle ↔ RSU

Uses

• ML-KEM Session Keys
• AES-GCM Encryption
• QRNG Nonces
• Message Integrity

Author : Meeth Amin
=========================================================
"""

import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import qrng


from models import Vehicle
from models import RSU


class SecureMessageTransfer:

    """
    Secure Message Transfer Manager
    """

      # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        session_manager
    ):

        self.session_manager = session_manager

        # ===============================================
        # Replay Protection
        # ===============================================

        self.used_nonces = set()

        # ===============================================
        # Statistics
        # ===============================================

        self.messages_sent = 0

        self.messages_received = 0

        self.failed_messages = 0

        self.encryption_times = []

        self.decryption_times = []

        # ===============================================
        # Communication Logs
        # ===============================================

        self.message_logs = []

        print("\nSecure Message Transfer Initialized")
        # ===============================================
        # Replay Protection
        # ===============================================

        self.used_nonces = set()

        # ===============================================
        # Statistics
        # ===============================================

        self.messages_sent = 0

        self.messages_received = 0

        self.failed_messages = 0

        self.encryption_times = []

        self.decryption_times = []

        # ===============================================
        # Communication Logs
        # ===============================================

        self.message_logs = []

        print("\nSecure Message Transfer Initialized")
            # =====================================================
    # Encrypt Message
    # =====================================================

    def encrypt_message(
        self,
        sender,
        receiver,
        plaintext
    ):
        """
        Encrypt a message using the established
        ML-KEM session key.
        """

        print("\nEncrypting Secure Message...")

        start = time.perf_counter()

        # -------------------------------------------------
        # Convert Message to Bytes
        # -------------------------------------------------

        if isinstance(plaintext, str):

            plaintext = plaintext.encode()

        # -------------------------------------------------
        # Retrieve Session Key
        # -------------------------------------------------

        responder_id = (

            receiver.real_id

            if isinstance(receiver, Vehicle)

            else receiver.rsu_id

        )

        session_key = self.session_manager.get_session_key(

            sender.real_id,

            responder_id

        )

        if session_key is None:

            self.failed_messages += 1

            print("No Active Session Key Found")

            return None

        # -------------------------------------------------
        # AES-GCM Initialization
        # -------------------------------------------------

        aesgcm = AESGCM(session_key)

        nonce = qrng.generate_random_bytes(12)

        ciphertext = aesgcm.encrypt(

            nonce,

            plaintext,

            None

        )

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        self.encryption_times.append(

            elapsed

        )

        self.messages_sent += 1

        # -------------------------------------------------
        # Communication Packet
        # -------------------------------------------------

        packet = {

            "sender":

                sender.real_id,

            "receiver":

                responder_id,

            "nonce":

                nonce,

            "ciphertext":

                ciphertext,

            "timestamp":

                int(time.time())

        }

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.message_logs.append({

            "direction":

                "SEND",

            "sender":

                sender.real_id,

            "receiver":

                responder_id,

            "time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print("Secure Message Encrypted")

        print(

            f"Encryption Time : "

            f"{elapsed:.3f} ms"

        )

        return packet
            # =====================================================
    # Decrypt Secure Message
    # =====================================================

    def decrypt_message(
        self,
        receiver,
        packet
    ):
        """
        Decrypt a secure message packet.
        """

        print("\nDecrypting Secure Message...")

        start = time.perf_counter()

        # -------------------------------------------------
        # Replay Protection
        # -------------------------------------------------

        nonce_hex = packet["nonce"].hex()

        if nonce_hex in self.used_nonces:

            self.failed_messages += 1

            print("Replay Attack Detected")

            return None

        self.used_nonces.add(nonce_hex)

        # -------------------------------------------------
        # Session Key Lookup
        # -------------------------------------------------

        sender_id = packet["sender"]

        receiver_id = (

            receiver.real_id

            if isinstance(receiver, Vehicle)

            else receiver.rsu_id

        )

        session_key = self.session_manager.get_session_key(

            sender_id,

            receiver_id

        )

        if session_key is None:

            self.failed_messages += 1

            print("No Active Session Found")

            return None

        # -------------------------------------------------
        # AES-GCM Decryption
        # -------------------------------------------------

        aesgcm = AESGCM(session_key)

        try:

            plaintext = aesgcm.decrypt(

                packet["nonce"],

                packet["ciphertext"],

                None

            )

        except Exception:

            self.failed_messages += 1

            print("Message Integrity Verification Failed")

            return None

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        self.messages_received += 1

        self.decryption_times.append(

            elapsed

        )

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        self.message_logs.append({

            "direction":

                "RECEIVE",

            "sender":

                sender_id,

            "receiver":

                receiver_id,

            "time":

                elapsed,

            "timestamp":

                int(time.time())

        })

        print("Secure Message Decrypted")

        print(

            f"Decryption Time : "

            f"{elapsed:.3f} ms"

        )

        return plaintext.decode()
            # =====================================================
    # Send Secure Message
    # =====================================================

    def send_message(
        self,
        sender,
        receiver,
        message
    ):
        """
        Encrypt and prepare a secure packet.
        """

        packet = self.encrypt_message(

            sender,

            receiver,

            message

        )

        if packet is None:

            print("Secure Message Transmission Failed")

            return None

        print("Secure Message Sent")

        return packet


    # =====================================================
    # Receive Secure Message
    # =====================================================

    def receive_message(
        self,
        receiver,
        packet
    ):
        """
        Receive and decrypt a secure packet.
        """

        message = self.decrypt_message(

            receiver,

            packet

        )

        if message is None:

            print("Secure Message Reception Failed")

            return None

        print("Secure Message Received")

        return message


    # =====================================================
    # Check Active Session
    # =====================================================

    def has_active_session(
        self,
        sender,
        receiver
    ):
        """
        Determine whether an active session exists.
        """

        receiver_id = (

            receiver.real_id

            if isinstance(receiver, Vehicle)

            else receiver.rsu_id

        )

        session = self.session_manager.get_session_key(

            sender.real_id,

            receiver_id

        )

        return session is not None
            # =====================================================
    # Secure Send
    # =====================================================

    def secure_send(
        self,
        sender,
        receiver,
        message
    ):
        """
        Complete secure message transmission.
        """

        print("\n" + "=" * 70)
        print("SECURE MESSAGE TRANSMISSION")
        print("=" * 70)

        # -------------------------------------------------
        # Check Active Session
        # -------------------------------------------------

        if not self.has_active_session(

            sender,

            receiver

        ):

            print("No Active Session Available")

            return None

        # -------------------------------------------------
        # Encrypt Message
        # -------------------------------------------------

        packet = self.send_message(

            sender,

            receiver,

            message

        )

        if packet is None:

            return None

        print("Transmission Successful")

        return packet


    # =====================================================
    # Secure Receive
    # =====================================================

    def secure_receive(
        self,
        receiver,
        packet
    ):
        """
        Complete secure message reception.
        """

        print("\nReceiving Secure Packet...")

        message = self.receive_message(

            receiver,

            packet

        )

        if message is None:

            return None

        print("Message Integrity Verified")

        print("Secure Reception Successful")

        return message


    # =====================================================
    # Display Communication Logs
    # =====================================================

    def show_logs(self):

        print("\n" + "=" * 70)

        print("SECURE MESSAGE LOGS")

        print("=" * 70)

        if not self.message_logs:

            print("No Messages Recorded")

            return

        for log in self.message_logs:

            print(log)

        print("=" * 70)
            # =====================================================
    # Display Statistics
    # =====================================================

    def show_statistics(self):

        print("\n" + "=" * 70)
        print("SECURE MESSAGE TRANSFER STATISTICS")
        print("=" * 70)

        print(
            f"Messages Sent         : "
            f"{self.messages_sent}"
        )

        print(
            f"Messages Received     : "
            f"{self.messages_received}"
        )

        print(
            f"Failed Messages       : "
            f"{self.failed_messages}"
        )

        print(
            f"Replay Nonces Stored  : "
            f"{len(self.used_nonces)}"
        )

        if self.encryption_times:

            avg_encrypt = (

                sum(self.encryption_times)

                /

                len(self.encryption_times)

            )

            print(

                f"Average Encryption Time : "

                f"{avg_encrypt:.3f} ms"

            )

        else:

            print(

                "Average Encryption Time : 0.000 ms"

            )

        if self.decryption_times:

            avg_decrypt = (

                sum(self.decryption_times)

                /

                len(self.decryption_times)

            )

            print(

                f"Average Decryption Time : "

                f"{avg_decrypt:.3f} ms"

            )

        else:

            print(

                "Average Decryption Time : 0.000 ms"

            )

        print("=" * 70)


    # =====================================================
    # Export Statistics
    # =====================================================

    def get_statistics(self):

        average_encrypt = (

            sum(self.encryption_times)

            /

            len(self.encryption_times)

            if self.encryption_times

            else 0.0

        )

        average_decrypt = (

            sum(self.decryption_times)

            /

            len(self.decryption_times)

            if self.decryption_times

            else 0.0

        )

        return {

            "messages_sent":

                self.messages_sent,

            "messages_received":

                self.messages_received,

            "failed_messages":

                self.failed_messages,

            "average_encryption_time":

                average_encrypt,

            "average_decryption_time":

                average_decrypt,

            "encryption_times":

                self.encryption_times.copy(),

            "decryption_times":

                self.decryption_times.copy(),

            "message_logs":

                self.message_logs.copy()

        }


    # =====================================================
    # Reset Statistics
    # =====================================================

    def reset_statistics(self):

        self.used_nonces.clear()

        self.messages_sent = 0

        self.messages_received = 0

        self.failed_messages = 0

        self.encryption_times.clear()

        self.decryption_times.clear()

        self.message_logs.clear()

        print("Secure Message Statistics Reset")


    # =====================================================
    # String Representation
    # =====================================================

    def __str__(self):

        return (

            f"SecureMessageTransfer("

            f"Sent={self.messages_sent}, "

            f"Received={self.messages_received}, "

            f"Failed={self.failed_messages})"

        )
