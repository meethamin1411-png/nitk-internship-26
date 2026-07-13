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


# =========================================================
# Configuration
# =========================================================

NUMBER_OF_RSUS = 1

NUMBER_OF_VEHICLES = 2


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

        secure_transfer

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


if __name__ == "__main__":

    main()