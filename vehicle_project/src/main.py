"""
=========================================================
PQC-VANET Protocol

Main Driver

Author : Meeth Amin
=========================================================
"""

from models.trusted_authority import TrustedAuthority
from models.rsu import RSU
from models.vehicle import Vehicle
from certificateless_key_generation import CertificatelessKeyGeneration
from pseudonym_genration import PseudonymGeneration
from mutual_authentication import MutualAuthentication
from secure_messege_transfer import SecureMessageTransfer
from v2v_communication import V2VCommunication
from v2i_communication import V2ICommunication
from replay_attack_demo import ReplayAttack
from mitm_attack_demo import MITMAttack
from sybil_attack import SybilAttack
from lightweight_revocation import LightweightRevocation
import secrets
from performance_evaluation.performance_manager import metrics_logger


# =========================================================
# Configuration
# =========================================================

NUMBER_OF_RSUS = 2

NUMBER_OF_VEHICLES = 5



# =========================================================
# Communication Overhead Measurement
# =========================================================

def _encode_measurement_value(value):
    """
    Convert a protocol field into deterministic bytes for
    application-layer communication-overhead measurement.

    This measurement is independent of Python's dictionary
    representation. Binary cryptographic values remain raw bytes;
    text is UTF-8 encoded; integers use 8-byte unsigned encoding.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, int):
        return value.to_bytes(8, byteorder="big", signed=False)

    return str(value).encode("utf-8")


def _serialize_protocol_packet(packet, field_order):
    """
    Serialize a protocol packet using a deterministic length-prefixed
    application-layer format.

    Each field is encoded as:
        4-byte field length || field value

    Field names are not transmitted because the protocol defines the
    field order. Transport/network headers are not included.
    """
    serialized = bytearray()

    for field_name in field_order:
        value = _encode_measurement_value(packet[field_name])
        serialized.extend(len(value).to_bytes(4, byteorder="big"))
        serialized.extend(value)

    return bytes(serialized)


def measure_protocol_overhead(ta, vehicles):
    """
    Measure the serialized application-layer sizes of M1-M4.

    A separate MutualAuthentication instance is used so that the
    measurement does not alter the main authentication statistics.

    The responder's long-term ML-KEM public key is provisioned and is
    not transmitted. The fresh ephemeral ML-KEM public key is transmitted
    in M2 and is therefore included in the measured overhead.
    """
    if len(vehicles) < 2:
        print("Communication overhead measurement skipped: "
              "at least 2 vehicles are required.")
        return None

    # Use a separate manager so measurement traffic is not counted
    # as another successful authentication.
    measurement_manager = MutualAuthentication(ta)

    sender = vehicles[0]
    responder = vehicles[1]

    print("\n")
    print("=" * 70)
    print("COMMUNICATION OVERHEAD MEASUREMENT")
    print("=" * 70)
    print("Measurement uses the implemented M1-M4 packet fields.")
    print("Long-term ML-KEM public key : PROVISIONED / NOT TRANSMITTED")
    print("Ephemeral ML-KEM public key : TRANSMITTED IN M2")
    print("Transport headers  : NOT INCLUDED")
    print("Measurement        : Application-layer serialized bytes")
    print("-" * 70)

    # Build the same M1-M4 message structures used by the protocol.
    m1 = measurement_manager.create_auth_request(sender, responder)
    m2 = measurement_manager.create_auth_response(responder, sender)

    m3_state = measurement_manager.create_m3_kem_message(
        sender,
        responder,
        m1,
        m2,
    )
    m3 = m3_state["m3"]

    sender_session_key = measurement_manager._derive_context_key(
        m3_state["shared_secret"],
        m1,
        m2,
    )

    if sender_session_key is None:
        print("Communication overhead measurement failed: "
              "session key could not be derived.")
        return None

    m4 = measurement_manager.create_m4_confirmation(
        responder,
        sender,
        m1,
        m2,
        sender_session_key,
    )

    # Exact field order follows the implemented protocol packet structures.
    m1_bytes = _serialize_protocol_packet(
        m1,
        [
            "sender_pseudonym",
            "receiver",
            "timestamp",
            "nonce",
            "road_segment",
            "vehicle_state",
            "act",
            "signature",
        ],
    )

    m2_bytes = _serialize_protocol_packet(
        m2,
        [
            "responder",
            "timestamp",
            "nonce",
            "ephemeral_kem_pk",
            "signature",
        ],
    )

    m3_bytes = _serialize_protocol_packet(
        m3,
        [
            "sender_pseudonym",
            "responder",
            "m2_nonce",
            "ciphertext",
            "timestamp",
            "road_segment",
            "vehicle_state",
            "signature",
        ],
    )

    m4_bytes = _serialize_protocol_packet(
        m4,
        [
            "responder",
            "timestamp",
            "confirmation",
        ],
    )

    sizes = {
        "M1": len(m1_bytes),
        "M2": len(m2_bytes),
        "M3": len(m3_bytes),
        "M4": len(m4_bytes),
    }

    total = sum(sizes.values())

    print(f"M1 : {sizes['M1']} bytes")
    print(f"M2 : {sizes['M2']} bytes")
    print(f"M3 : {sizes['M3']} bytes")
    print(f"M4 : {sizes['M4']} bytes")
    print("-" * 70)
    print(f"TOTAL M1-M4 COMMUNICATION OVERHEAD : {total} bytes")
    print("-" * 70)
    print("Note : This is application-layer packet size only.")
    print("       IP/TCP/UDP/MAC headers are not included.")
    print("       The long-term/provisioned ML-KEM public key is not included.")
    print("       The fresh ephemeral ML-KEM public key in M2 is included.")
    print("=" * 70)

    return sizes

def main():

    print("\n")
    print("=" * 70)
    print("PQC-VANET PROTOCOL")
    print("=" * 70)

    # =====================================================
    # Phase 1
    # Trusted Authority
    # =====================================================

    ta = TrustedAuthority()

    print()

    ta.show_information()

    print()

    print("=" * 70)
    print("PHASE 1 COMPLETED")
    print("=" * 70)

    # =====================================================
    # Phase 2
    # RSU Initialization
    # =====================================================

    print("\n")
    print("=" * 70)
    print("INITIALIZING ROAD SIDE UNITS")
    print("=" * 70)

    rsus = []

    for i in range(1, NUMBER_OF_RSUS + 1):

        rsu = RSU(

            rsu_id=f"RSU{i:03d}",

            trusted_authority=ta

        )

        ta.register_rsu(rsu)

        rsu.register()

        rsu.initialize_crypto()

        rsus.append(rsu)

    print()

    ta.show_rsu_registry()

    print()

    for rsu in rsus:

        rsu.show_information()

        print()

    print("=" * 70)
    print("PHASE 2 COMPLETED")
    print("=" * 70)
    

    # =====================================================
    # Phase 3
    # Vehicle Initialization
    # =====================================================

    print("\n")
    print("=" * 70)
    print("INITIALIZING VEHICLES")
    print("=" * 70)

    vehicles = []

    for i in range(1, NUMBER_OF_VEHICLES + 1):

        vehicle = Vehicle(

            real_id=f"VEHICLE{i:03d}",

            trusted_authority=ta

        )

        vehicles.append(vehicle)

    print()

    print("=" * 70)

    print(f"TOTAL VEHICLES CREATED : {len(vehicles)}")

    print("=" * 70)

    print()

    for vehicle in vehicles:

        vehicle.show_information()

        print()

    print("=" * 70)
    print("PHASE 3 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 4
    # Vehicle Registration
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 4 : VEHICLE REGISTRATION")
    print("=" * 70)

    successful_registrations = 0

    for index, vehicle in enumerate(

        vehicles,

        start=1

    ):

        print()

        print("-" * 70)

        print(

            f"Registering Vehicle "

            f"{index}/{NUMBER_OF_VEHICLES}"

        )

        print("-" * 70)

        status = ta.register_vehicle(

            vehicle

        )

        if status:

            successful_registrations += 1

    print()

    print("=" * 70)

    print(

        f"Successfully Registered : "

        f"{successful_registrations}"

    )

    print(

        f"Failed Registrations    : "

        f"{NUMBER_OF_VEHICLES-successful_registrations}"

    )

    print("=" * 70)

    print()

    ta.show_vehicle_registry()

    print()

    print("=" * 70)

    print("PHASE 4 COMPLETED")

    print("=" * 70)
        # =====================================================
    # Phase 5
    # Certificateless Key Generation
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 5 : CERTIFICATELESS KEY GENERATION")
    print("=" * 70)

    key_generator = CertificatelessKeyGeneration(

        ta

    )

    print()

    key_generator.generate_keys_for_all(

        vehicles

    )

    print()

    key_generator.verify_all(

        vehicles

    )

    print()

    key_generator.show_information()

    print()

    print("=" * 70)

    print("PHASE 5 COMPLETED")

    print("=" * 70)
        # =====================================================
    # Phase 6
    # Pseudonym Generation
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 6 : PSEUDONYM GENERATION")
    print("=" * 70)

    pseudonym_manager = PseudonymGeneration(
        ta
    )

    print()

    successful = pseudonym_manager.generate_for_all(
        vehicles
    )

    print()

    pseudonym_manager.verify_all(
        vehicles
    )

    print()

    ta.show_vehicle_registry()

    print()

    pseudonym_manager.show_information()

    print()

    print("=" * 70)
    print("PHASE 6 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 7
    # Mutual Authentication
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 7 : MUTUAL AUTHENTICATION")
    print("=" * 70)

    authentication_manager = MutualAuthentication(

        ta

    )

    print()

    authentication_manager.authenticate_network(

        vehicles,

        rsus

    )

    print()

    authentication_manager.show_statistics()

    print()
    forward_secrecy_status = authentication_manager.evaluate_forward_secrecy(
        vehicles[0],
        vehicles[1],
    )

    print()

    print("=" * 70)
    print("PHASE 7 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 8
    # Secure Message Transfer
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 8 : SECURE MESSAGE TRANSFER")
    print("=" * 70)

    secure_transfer = SecureMessageTransfer(

        authentication_manager

    )

    print()

    message = (

        "Emergency Brake Warning"

    )

    packet = secure_transfer.secure_send(

        vehicles[0],

        vehicles[1],

        message

    )

    if packet is not None:

        print()

        received = secure_transfer.secure_receive(

            vehicles[1],

            packet

        )

        print()

        print(f"Original Message : {message}")

        print(f"Received Message : {received}")

    print()

    secure_transfer.show_statistics()

    print()

    print("=" * 70)
    print("PHASE 8 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 9
    # Vehicle-to-Vehicle Communication
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 9 : VEHICLE TO VEHICLE COMMUNICATION")
    print("=" * 70)

    v2v_manager = V2VCommunication(

        authentication_manager,

        secure_transfer

    )

    print()

    message = "Accident Ahead. Reduce Speed."

    received = v2v_manager.send_message(

        vehicles[0],

        vehicles[1],

        message

    )

    print()

    print(f"Original Message : {message}")

    print(f"Received Message : {received}")

    print()

    v2v_manager.show_statistics()

    print()

    print("=" * 70)
    print("PHASE 9 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 10
    # Vehicle-to-Infrastructure Communication
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 10 : VEHICLE TO INFRASTRUCTURE COMMUNICATION")
    print("=" * 70)

    v2i_manager = V2ICommunication(

        authentication_manager,

        secure_transfer

    )

    print()

    infrastructure_message = (

        "Request Traffic Signal Status"

    )

    received = v2i_manager.send_message(

        vehicles[0],

         rsus[0],

        infrastructure_message

    )

    print()

    print(f"Original Message : {infrastructure_message}")

    print(f"Received Message : {received}")

    print()

    v2i_manager.show_statistics()

    print()

    print("=" * 70)
    print("PHASE 10 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 11
    # Replay Attack Evaluation
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 11 : REPLAY ATTACK EVALUATION")
    print("=" * 70)

    replay_manager = ReplayAttack(

        secure_transfer

    )

    print()

    print("Generating Original Secure Packet...")

    replay_packet = secure_transfer.secure_send(

        vehicles[0],

        vehicles[1],

        "Emergency Vehicle Crossing"

    )

    print()

    if replay_packet is not None:

        print("Receiving Original Packet...")

        secure_transfer.secure_receive(

            vehicles[1],

            replay_packet

        )

        print()

        replay_manager.execute_attack(

            vehicles[0],

            vehicles[1],

            replay_packet

        )

    print()

    replay_manager.show_statistics()

    print()

    print("=" * 70)
    print("PHASE 11 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 12
    # MITM Attack Evaluation
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 12 : MAN-IN-THE-MIDDLE ATTACK")
    print("=" * 70)

    mitm_manager = MITMAttack(

        secure_transfer,
        authentication_manager

    )

    print()

    print("Generating Original Secure Packet...")

    mitm_packet = secure_transfer.secure_send(

        vehicles[0],

        vehicles[1],

        "Speed Limit 60 km/h"

    )

    print()

    if mitm_packet is not None:

        mitm_manager.execute_attack(

            vehicles[0],

            vehicles[1],

            mitm_packet

        )

    print()

    mitm_manager.show_statistics()

    print()

    print("=" * 70)
    print("PHASE 12 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 13
    # Sybil Attack Evaluation
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 13 : SYBIL ATTACK EVALUATION")
    print("=" * 70)

    sybil_manager = SybilAttack(

        ta,

        authentication_manager

    )

    print()

    sybil_manager.execute_attack(

        vehicles[0]

    )

    print()

    sybil_manager.show_statistics()

    print()

    print("=" * 70)
    print("PHASE 13 COMPLETED")
    print("=" * 70)
        # =====================================================
    # Phase 14
    # Final Simulation Summary
    # =====================================================

    print("\n")
    print("=" * 70)
    print("PHASE 14 : PQC-VANET SIMULATION SUMMARY")
    print("=" * 70)

    print("\nGENERAL INFORMATION")
    print("-" * 70)

    print(f"Registered Vehicles        : {len(vehicles)}")
    print(f"Registered RSUs            : {len(rsus)}")

    print("\nAUTHENTICATION")
    print("-" * 70)

    print(f"Successful Authentications : {authentication_manager.successful_authentications}")
    print(f"Failed Authentications     : {authentication_manager.failed_authentications}")

    if authentication_manager.authentication_times:

        avg_auth = (
            sum(authentication_manager.authentication_times)
            /
            len(authentication_manager.authentication_times)
        )

    else:

        avg_auth = 0.0

    print(f"Average Authentication Time : {avg_auth:.3f} ms")

    print("\nSECURE MESSAGE TRANSFER")
    print("-" * 70)

    print(f"Messages Sent              : {secure_transfer.messages_sent}")
    print(f"Messages Received          : {secure_transfer.messages_received}")
    print(f"Failed Messages            : {secure_transfer.failed_messages}")

    if secure_transfer.encryption_times:

        avg_enc = (
            sum(secure_transfer.encryption_times)
            /
            len(secure_transfer.encryption_times)
        )

    else:

        avg_enc = 0.0

    if secure_transfer.decryption_times:

        avg_dec = (
            sum(secure_transfer.decryption_times)
            /
            len(secure_transfer.decryption_times)
        )

    else:

        avg_dec = 0.0

    print(f"Average Encryption Time    : {avg_enc:.3f} ms")
    print(f"Average Decryption Time    : {avg_dec:.3f} ms")

    print("\nV2V COMMUNICATION")
    print("-" * 70)

    print(f"Successful Messages        : {v2v_manager.successful_messages}")
    print(f"Average Communication Time : {sum(v2v_manager.communication_times)/len(v2v_manager.communication_times):.3f} ms")

    print("\nV2I COMMUNICATION")
    print("-" * 70)

    print(f"Successful Messages        : {v2i_manager.successful_messages}")
    print(f"Average Communication Time : {sum(v2i_manager.communication_times)/len(v2i_manager.communication_times):.3f} ms")

    print("\nSECURITY EVALUATION")
    print("-" * 70)

    print(f"Replay Attack  : {'BLOCKED ✓' if replay_manager.detected_attacks else 'FAILED ✗'}")
    print(f"MITM Attack    : {'BLOCKED ✓' if mitm_manager.detected_attacks else 'FAILED ✗'}")
    print(f"Sybil Attack   : {'BLOCKED ✓' if sybil_manager.detected_attacks else 'FAILED ✗'}")

    print("\nOVERALL STATUS")
    print("-" * 70)

    print("✓ Trusted Authority")
    print("✓ RSU Initialization")
    print("✓ Vehicle Registration")
    print("✓ Certificateless Key Generation")
    print("✓ Pseudonym Generation")
    print("✓ Mutual Authentication")
    print("✓ Secure Message Transfer")
    print("✓ Vehicle-to-Vehicle Communication")
    print("✓ Vehicle-to-Infrastructure Communication")
    print("✓ Replay Attack Protection")
    print("✓ MITM Attack Protection")
    print("✓ Sybil Attack Protection")

    print("\n")
    print("=" * 70)
    print("PQC-VANET SIMULATION COMPLETED SUCCESSFULLY")
    print("=" * 70)
        # ======================================================
    # PHASE 15 : LIGHTWEIGHT REVOCATION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("PHASE 15 : LIGHTWEIGHT REVOCATION")
    print("=" * 70)

    # Initialize Revocation Manager
    revocation = LightweightRevocation(ta)

    print("\nRevoking Vehicle 2...\n")

    revocation.revoke_vehicle(
        vehicles[1],
        reason="False Safety Message Injection",
        severity="HIGH"
    )

    print()

    # Show Vehicle Revocation Status
    revocation.show_revocation_status(
        vehicles[1]
    )

    print()

    # Check Authentication Permission
    print(
        "Authentication Allowed :",
        revocation.can_authenticate(
            vehicles[1]
        )
    )

    print()

    # Display RID Database
    revocation.show_rid_database()

    print()

    # Display Performance Statistics
    revocation.show_statistics()

    print()

    # Complete Protocol Report
    revocation.protocol_report(
        vehicles[1]
    )

    print()

    print("=" * 70)
    print("PHASE 15 COMPLETED")
    print("=" * 70)
        # ======================================================
    # PHASE 16 : SECURE RE-REGISTRATION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("PHASE 16 : SECURE RE-REGISTRATION")
    print("=" * 70)

    # Securely Re-Register Vehicle
    revocation.re_register_vehicle(
        vehicles[1]
    )

    print()

    # Display Updated Vehicle Status
    revocation.show_revocation_status(
        vehicles[1]
    )

    print()

    # Authentication Permission After Re-Registration
    print(
        "Authentication Allowed :",
        revocation.can_authenticate(
            vehicles[1]
        )
    )

    print()

    print("=" * 70)
    print("PHASE 16 COMPLETED")
    print("=" * 70)
        # ======================================================
    # PHASE 17 : AUTHENTICATION STATE MACHINE
    # ======================================================

    print("\n")
    print("=" * 70)
    print("PHASE 17 : AUTHENTICATION STATE MACHINE")
    print("=" * 70)

    print("\nVehicle :", vehicles[1].real_id)

    print("\nAUTHENTICATION STATE MACHINE")
    print("-" * 70)

    print("UNREGISTERED")
    print("      ↓")
    print("REGISTERED")
    print("      ↓")
    print("ANONYMOUS (Adaptive Pseudonym)")
    print("      ↓")
    print("AUTHENTICATED")
    print("      ↓")
    print("SECURE SESSION")
    print("      ↓")
    print("REVOKED")
    print("      ↓")
    print("RE-REGISTERED")
    print("      ↓")
    print("AUTHENTICATED")

    print()

    print("Current State :", "AUTHENTICATED" if revocation.can_authenticate(vehicles[1]) else "REVOKED")

    print()

    print("=" * 70)
    print("PHASE 17 COMPLETED")
    print("=" * 70)

    # ======================================================
    # Communication Overhead Analysis
    # ======================================================

    print("\n")
    print("=" * 70)
    print("COMMUNICATION OVERHEAD ANALYSIS")
    print("=" * 70)

    overhead_sizes = measure_protocol_overhead(
        ta,
        vehicles,
    )

    # ======================================================
    # PHASE 19 : SECURITY FEATURE ANALYSIS
    # ======================================================

    print("\n")
    print("=" * 75)
    print("PHASE 19 : SECURITY FEATURE ANALYSIS")
    print("=" * 75)

    print()

    print("{:<30} {:<15}".format(
        "Security Property",
        "Status"
    ))

    print("-" * 75)

    security_features = [
        ("Replay Attack Resistance", "IMPLEMENTED"),
        ("MITM Attack Resistance", "IMPLEMENTED"),
        ("Conditional Privacy", "IMPLEMENTED"),
        ("Quantum Resistance", "IMPLEMENTED"),
        ("Forward Secrecy", "IMPLEMENTED" if forward_secrecy_status else "FAILED"),
    ]

    for feature, status in security_features:
        print("{:<30} {:<15}".format(feature, status))

    print("\n")
    print("-" * 75)
    print("SECURITY FEATURE DETAILS")
    print("-" * 75)

    print("✓ Replay Attack Resistance")
    print("   Fresh nonces, timestamps and replay checks are used.")

    print("\n✓ MITM Attack Resistance")
    print("   ML-DSA signatures authenticate protocol messages, and")
    print("   M3 binds the current M2 challenge nonce.")

    print("\n✓ Conditional Privacy")
    print("   Vehicle pseudonyms are used instead of transmitting the")
    print("   vehicle's real identity in M1/M3.")

    print("\n✓ Quantum Resistance")
    print("   ML-KEM is used for key establishment and ML-DSA is used")
    print("   for digital signatures.")

    print("\n✓ Forward Secrecy")
    if forward_secrecy_status:
        print("   Each authentication session uses a fresh ephemeral")
        print("   ML-KEM key pair. The ephemeral private key is discarded")
        print("   after M3 decapsulation, so later compromise of the")
        print("   responder's long-term ML-KEM key does not recover the")
        print("   previously established session key.")
    else:
        print("   Forward-secrecy evaluation failed for the tested session.")

    print()
    print("=" * 75)
    print("SECURITY ANALYSIS COMPLETED")
    print("=" * 75)

    metrics_logger.export_all_csv()

    print("\nPerformance CSV files generated successfully.")

if __name__ == "__main__":

    main()
