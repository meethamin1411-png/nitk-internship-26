"""
=============================================================
ML-DSA (Dilithium) Professional Benchmark Suite
-------------------------------------------------------------
Research Version 2.0

Features
--------
• 100 Iterations
• Timing Statistics
• CSV Export
• Automatic Graph Generation
• Throughput Calculation
• Standard Deviation
• Key Size Analysis

Author : Meeth Amin
=============================================================
"""

import os
import sys
import csv
import time
import statistics
from pathlib import Path

import matplotlib.pyplot as plt

# ------------------------------------------------------------
# Allow imports from src/
# ------------------------------------------------------------

CURRENT_DIR = Path(__file__).resolve().parent

SRC_DIR = CURRENT_DIR.parent

if str(SRC_DIR) not in sys.path:

    sys.path.insert(0, str(SRC_DIR))

from crypto import dilithium


ITERATIONS = 100


RESULT_FOLDER = CURRENT_DIR / "benchmark_results"

RESULT_FOLDER.mkdir(exist_ok=True)
# ============================================================
# Dilithium Benchmark Class
# ============================================================

class DilithiumBenchmark:

    def __init__(self):

        self.keygen_times = []

        self.sign_times = []

        self.verify_times = []

        self.public_key_size = 0

        self.private_key_size = 0

        self.signature_size = 0

        self.success_count = 0

        self.failure_count = 0

        self.message = (

            b"PQC-VANET ML-DSA Performance Benchmark"

        )

    # ========================================================
    # Print Header
    # ========================================================

    def print_header(self):

        print("\n" + "=" * 70)

        print("ML-DSA (DILITHIUM) PROFESSIONAL BENCHMARK")

        print("=" * 70)

        print()

        print(f"Iterations : {ITERATIONS}")

        print()
            # ========================================================
    # Benchmark Key Generation
    # ========================================================

    def benchmark_key_generation(self):

        print("Benchmarking ML-DSA Key Generation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            public_key, secret_key = (

                dilithium.generate_keypair()

            )

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.keygen_times.append(

                elapsed

            )

            self.public_key_size = len(

                public_key

            )

            self.private_key_size = len(

                secret_key

            )

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        self.public_key = public_key

        self.private_key = secret_key

        print()

        print("✓ Key Generation Benchmark Completed")

        print()
            # ========================================================
    # Benchmark Signature Generation
    # ========================================================

    def benchmark_signing(self):

        print("Benchmarking ML-DSA Signature Generation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            signature = (

                dilithium.sign_message(

                    self.private_key,

                    self.message

                )

            )

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.sign_times.append(

                elapsed

            )

            self.signature_size = len(

                signature

            )

            self.signature = signature

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Signature Generation Benchmark Completed")

        print()
            # ========================================================
    # Benchmark Signature Verification
    # ========================================================

    def benchmark_verification(self):

        print("Benchmarking ML-DSA Signature Verification...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            status = (

                dilithium.verify_signature(

                    self.public_key,

                    self.message,

                    self.signature

                )

            )

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.verify_times.append(

                elapsed

            )

            if status:

                self.success_count += 1

            else:

                self.failure_count += 1

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Signature Verification Benchmark Completed")

        print()

        self.verification_status = (

            self.failure_count == 0

        )
            # ========================================================
    # Export Results to CSV
    # ========================================================

    def export_csv(self):

        csv_file = RESULT_FOLDER / "dilithium_results.csv"

        with open(

            csv_file,

            "w",

            newline=""

        ) as file:

            writer = csv.writer(file)

            writer.writerow([

                "Iteration",

                "Key Generation (ms)",

                "Signing (ms)",

                "Verification (ms)"

            ])

            for i in range(ITERATIONS):

                writer.writerow([

                    i + 1,

                    self.keygen_times[i],

                    self.sign_times[i],

                    self.verify_times[i]

                ])

        print(

            f"✓ CSV Saved : {csv_file}"

        )

        print()
            # ========================================================
    # Generate Performance Graphs
    # ========================================================

    def generate_graphs(self):

        print("Generating Benchmark Graphs...")

        # ----------------------------------------------------
        # Key Generation Graph
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.keygen_times,

            linewidth=2

        )

        plt.title("ML-DSA Key Generation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "dilithium_key_generation.png",

            dpi=300

        )

        plt.close()

        # ----------------------------------------------------
        # Signing Graph
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.sign_times,

            linewidth=2

        )

        plt.title("ML-DSA Signature Generation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "dilithium_signing.png",

            dpi=300

        )

        plt.close()

        # ----------------------------------------------------
        # Verification Graph
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.verify_times,

            linewidth=2

        )

        plt.title("ML-DSA Signature Verification Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "dilithium_verification.png",

            dpi=300

        )

        plt.close()

        print()

        print("✓ Graphs Generated Successfully")

        print(f"✓ Saved in : {RESULT_FOLDER}")

        print()
            # ========================================================
    # Display Professional Report
    # ========================================================

    def display_report(self):

        print("\n" + "=" * 70)
        print("ML-DSA (DILITHIUM) PROFESSIONAL BENCHMARK REPORT")
        print("=" * 70)

        print(f"\nIterations                : {ITERATIONS}")

        print("\nKEY SIZES")
        print("-" * 70)

        print(f"Public Key Size           : {self.public_key_size} Bytes")
        print(f"Private Key Size          : {self.private_key_size} Bytes")
        print(f"Signature Size            : {self.signature_size} Bytes")

        print("\nKEY GENERATION")
        print("-" * 70)

        print(f"Average                   : {statistics.mean(self.keygen_times):.3f} ms")
        print(f"Minimum                   : {min(self.keygen_times):.3f} ms")
        print(f"Maximum                   : {max(self.keygen_times):.3f} ms")
        print(f"Std. Deviation            : {statistics.stdev(self.keygen_times):.3f} ms")

        print("\nSIGNATURE GENERATION")
        print("-" * 70)

        print(f"Average                   : {statistics.mean(self.sign_times):.3f} ms")
        print(f"Minimum                   : {min(self.sign_times):.3f} ms")
        print(f"Maximum                   : {max(self.sign_times):.3f} ms")
        print(f"Std. Deviation            : {statistics.stdev(self.sign_times):.3f} ms")

        print("\nSIGNATURE VERIFICATION")
        print("-" * 70)

        print(f"Average                   : {statistics.mean(self.verify_times):.3f} ms")
        print(f"Minimum                   : {min(self.verify_times):.3f} ms")
        print(f"Maximum                   : {max(self.verify_times):.3f} ms")
        print(f"Std. Deviation            : {statistics.stdev(self.verify_times):.3f} ms")

        sign_tp = 1000 / statistics.mean(self.sign_times)
        verify_tp = 1000 / statistics.mean(self.verify_times)

        print("\nTHROUGHPUT")
        print("-" * 70)

        print(f"Signing Throughput        : {sign_tp:.2f} signatures/sec")
        print(f"Verification Throughput   : {verify_tp:.2f} verifications/sec")

        print("\nRESULT")
        print("-" * 70)

        print(f"Successful Verifications  : {self.success_count}")
        print(f"Failed Verifications      : {self.failure_count}")

        print(
            f"Success Rate              : "
            f"{(self.success_count/ITERATIONS)*100:.2f}%"
        )

        print(
            f"Overall Status            : "
            f"{'SUCCESS' if self.verification_status else 'FAILED'}"
        )

        print("=" * 70)
        # ============================================================
# Main
# ============================================================

def main():

    benchmark = DilithiumBenchmark()

    benchmark.print_header()

    benchmark.benchmark_key_generation()

    benchmark.benchmark_signing()

    benchmark.benchmark_verification()

    benchmark.export_csv()

    benchmark.generate_graphs()

    benchmark.display_report()


if __name__ == "__main__":

    main()