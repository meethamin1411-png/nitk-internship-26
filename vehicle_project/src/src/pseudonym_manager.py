"""
=========================================================
Pseudonym Manager
PQC-VANET Protocol

Purpose:
    Manages dynamic vehicle pseudonyms,
    rotation history and privacy mode.
=========================================================
"""

from datetime import datetime

from common.protocol_types import (
    PrivacyMode,
    RotationReason,
)

from common.models import (
    ManagedPseudonym,
)

    # =========================================================
# Pseudonym Manager
# =========================================================

class PseudonymManager:
    """
    Manages vehicle pseudonyms,
    pseudonym history and rotations.
    """

    def __init__(self):

        # Current Active Pseudonym
        self._current_pseudonym: ManagedPseudonym | None = None

        # Previous Pseudonym
        self._previous_pseudonym: ManagedPseudonym | None = None

        # Complete History
        self._history: list[ManagedPseudonym] = []

        # Number of Rotations
        self._rotation_counter = 0
            # -----------------------------------------------------
    # Store New Pseudonym
    # -----------------------------------------------------

    def store_pseudonym(
        self,
        pid: str,
        privacy_mode: PrivacyMode,
        rotation_reason: RotationReason
    ):
        """
        Store a newly generated pseudonym.
        """

        # Save current as previous
        if self._current_pseudonym is not None:
            self._previous_pseudonym = self._current_pseudonym

        # Create new managed pseudonym
        new_pseudonym = ManagedPseudonym(

            pid=pid,

            privacy_mode=privacy_mode,

            created_at=datetime.now(),

            expires_at=None,

            rotation_reason=rotation_reason

        )

        # Update current pseudonym
        self._current_pseudonym = new_pseudonym

        # Store in history
        self._history.append(new_pseudonym)

        # Increase rotation counter
        self._rotation_counter += 1
            # -----------------------------------------------------
    # Rotate Pseudonym
    # -----------------------------------------------------

    def rotate_pseudonym(
        self,
        new_pid: str,
        privacy_mode: PrivacyMode,
        rotation_reason: RotationReason
    ):
        """
        Rotate to a newly generated pseudonym.
        """

        self.store_pseudonym(
            pid=new_pid,
            privacy_mode=privacy_mode,
            rotation_reason=rotation_reason
        )


    # -----------------------------------------------------
    # Get Current Pseudonym
    # -----------------------------------------------------

    def get_current_pseudonym(self) -> ManagedPseudonym | None:
        """
        Return the currently active pseudonym.
        """

        return self._current_pseudonym


    # -----------------------------------------------------
    # Get Previous Pseudonym
    # -----------------------------------------------------

    def get_previous_pseudonym(self) -> ManagedPseudonym | None:
        """
        Return the previous pseudonym.
        """

        return self._previous_pseudonym
            # -----------------------------------------------------
    # Get Complete History
    # -----------------------------------------------------

    def get_history(self) -> list[ManagedPseudonym]:
        """
        Return the complete pseudonym history.
        """

        return self._history


    # -----------------------------------------------------
    # Display Current Pseudonym
    # -----------------------------------------------------

    def display_current_pseudonym(self):
        """
        Display the currently active pseudonym.
        """

        print("\n")
        print("=" * 65)
        print("           CURRENT PSEUDONYM")
        print("=" * 65)

        if self._current_pseudonym is None:

            print("No Active Pseudonym")

        else:

            print(f"PID              : {self._current_pseudonym.pid}")
            print(f"Privacy Mode     : {self._current_pseudonym.privacy_mode.value}")
            print(f"Created At       : {self._current_pseudonym.created_at}")
            print(f"Expires At       : {self._current_pseudonym.expires_at}")
            print(f"Rotation Reason  : {self._current_pseudonym.rotation_reason.value}")

        print("=" * 65)
        print()


    # -----------------------------------------------------
    # Display Pseudonym History
    # -----------------------------------------------------

    def display_history(self):
        """
        Display complete pseudonym history.
        """

        print("\n")
        print("=" * 65)
        print("          PSEUDONYM HISTORY")
        print("=" * 65)

        if len(self._history) == 0:

            print("No Pseudonym History Available")

        else:

            for index, pseudonym in enumerate(self._history, start=1):

                print(f"\nRotation #{index}")

                print("-" * 40)

                print(f"PID             : {pseudonym.pid}")

                print(f"Privacy Mode    : {pseudonym.privacy_mode.value}")

                print(f"Created At      : {pseudonym.created_at}")

                print(f"Rotation Reason : {pseudonym.rotation_reason.value}")

        print("\n")
        print("=" * 65)

        print(f"Total Rotations : {self._rotation_counter}")

        print("=" * 65)
        print()
        # =========================================================
# Module Testing
# =========================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 70)
    print("         PQC-VANET PSEUDONYM MANAGER TEST")
    print("=" * 70)

    manager = PseudonymManager()

    # -------------------------------------------------
    # Initial Registration
    # -------------------------------------------------

    manager.store_pseudonym(

        pid="PID_001",

        privacy_mode=PrivacyMode.NORMAL,

        rotation_reason=RotationReason.INITIAL_REGISTRATION

    )

    # -------------------------------------------------
    # Authentication Rotation
    # -------------------------------------------------

    manager.rotate_pseudonym(

        new_pid="PID_002",

        privacy_mode=PrivacyMode.PRIVACY,

        rotation_reason=RotationReason.AUTHENTICATION

    )

    # -------------------------------------------------
    # Threat Change Rotation
    # -------------------------------------------------

    manager.rotate_pseudonym(

        new_pid="PID_003",

        privacy_mode=PrivacyMode.SECURE,

        rotation_reason=RotationReason.THREAT_CHANGE

    )

    # -------------------------------------------------
    # Display Results
    # -------------------------------------------------

    print("\nCURRENT ACTIVE PSEUDONYM")

    manager.display_current_pseudonym()

    print("\nCOMPLETE PSEUDONYM HISTORY")

    manager.display_history()

    print("\n")

    print("=" * 70)

    print("Pseudonym Manager Test Completed Successfully")

    print("=" * 70)