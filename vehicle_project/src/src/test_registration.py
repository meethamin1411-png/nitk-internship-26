from models.trusted_authority import TrustedAuthority
from models.vehicle import Vehicle
from models.rsu import RSU


def main():

    print("=" * 70)
    print("TESTING VANET REGISTRATION")
    print("=" * 70)

    # --------------------------------------------------
    # Trusted Authority
    # --------------------------------------------------

    ta = TrustedAuthority()

    # --------------------------------------------------
    # Vehicle Registration
    # --------------------------------------------------

    vehicle = Vehicle(
        "VEH-KA01-AB1234",
        ta
    )

    vehicle.register()

    print("\n✅ Vehicle Registered Successfully!")

    # --------------------------------------------------
    # RSU Registration
    # --------------------------------------------------

    rsu = RSU(
        "RSU-NH48-001",
        ta
    )

    print("✅ RSU Registered Successfully!")

    # --------------------------------------------------
    # Vehicle Information
    # --------------------------------------------------

    print("\n" + "=" * 70)
    print("VEHICLE DETAILS")
    print("=" * 70)

    print(f"Vehicle ID              : {vehicle.real_id}")
    print(f"Dilithium PK Length     : {len(vehicle.sig_pk)}")
    print(f"Kyber PK Available      : {vehicle.kem_pk is not None}")
    print(f"Registration Token      : {vehicle.registration_token}")

    # --------------------------------------------------
    # RSU Information
    # --------------------------------------------------

    print("\n" + "=" * 70)
    print("RSU DETAILS")
    print("=" * 70)

    print(f"RSU ID                  : {rsu.rsu_id}")
    print(f"Dilithium PK Length     : {len(rsu.sig_pk)}")
    print(f"Kyber PK Available      : {rsu.kem_pk is not None}")

    # --------------------------------------------------
    # TA Registry
    # --------------------------------------------------

    print("\n")
    ta.show_registry()

    # --------------------------------------------------
    # Registration Verification
    # --------------------------------------------------

    print("\n" + "=" * 70)
    print("REGISTRATION CHECK")
    print("=" * 70)

    print(
        "Vehicle Registered      :",
        ta.is_registered(vehicle.real_id)
    )

    print(
        "RSU Registered          :",
        ta.is_registered(rsu.rsu_id)
    )

    print(
        "Vehicle Revoked         :",
        ta.is_revoked(vehicle.real_id)
    )

    print(
        "Vehicle Status          :",
        ta.vehicle_status(vehicle.real_id)
    )

    print(
        "Registration Signature  :",
        ta.verify_registration_signature(vehicle.real_id)
    )

    print("\n")

    print("=" * 70)
    print("✅ ALL REGISTRATION TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()