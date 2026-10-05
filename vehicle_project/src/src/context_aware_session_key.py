import hashlib
import time


class ContextAwareSessionKey:
    """
    Context-Aware Session Key Derivation

    Final Session Key =
        SHA3-256(
            Shared Secret ||
            Session Nonce ||
            Road ID ||
            Adaptive PID ||
            Timestamp
        )
    """

    def __init__(self):
        self.generated_keys = 0
        self.failed_keys = 0
        self.execution_times = []

    def derive_session_key(
        self,
        shared_secret: bytes,
        session_nonce: str,
        road_id: str,
        pseudonym: str,
        timestamp: str,
    ):
        """
        Derive a context-aware session key.
        """

        print("\n" + "=" * 70)
        print("CONTEXT-AWARE SESSION KEY DERIVATION")
        print("=" * 70)

        start = time.perf_counter()

        try:

            print("\nCollecting Context Parameters...")

            data = (
                shared_secret
                + session_nonce.encode()
                + road_id.encode()
                + pseudonym.encode()
                + timestamp.encode()
            )

            print("✓ Shared Secret")
            print("✓ Session Nonce")
            print("✓ Road ID")
            print("✓ Adaptive PID")
            print("✓ Timestamp")

            print("\nDeriving Final Session Key...")

            final_key = hashlib.sha3_256(data).digest()

            elapsed = (time.perf_counter() - start) * 1000

            self.generated_keys += 1
            self.execution_times.append(elapsed)

            print("✓ Context-Aware Session Key Generated")
            print(f"Derivation Time : {elapsed:.3f} ms")

            return final_key

        except Exception as e:

            self.failed_keys += 1

            print("Session Key Derivation Failed")
            print(e)

            return None

    def verify_session_key(self, key: bytes):

        return key is not None and len(key) == 32

    def print_statistics(self):

        avg = (
            sum(self.execution_times) / len(self.execution_times)
            if self.execution_times
            else 0
        )

        print("\n" + "=" * 70)
        print("CONTEXT-AWARE SESSION KEY STATISTICS")
        print("=" * 70)
        print(f"Generated Keys : {self.generated_keys}")
        print(f"Failed Keys    : {self.failed_keys}")
        print(f"Average Time   : {avg:.3f} ms")
        print("=" * 70)