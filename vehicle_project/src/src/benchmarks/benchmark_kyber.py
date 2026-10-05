"""
=============================================================
ML-KEM (Kyber) Professional Benchmark Suite
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

import csv
import os
import sys
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

from crypto import kyber


ITERATIONS = 100


RESULT_FOLDER = CURRENT_DIR / "benchmark_results"

RESULT_FOLDER.mkdir(exist_ok=True)
# ============================================================
# Kyber Benchmark Class
# ============================================================

class KyberBenchmark:

    def __init__(self):

        self.keygen_times = []

        self.encapsulation_times = []

        self.decapsulation_times = []

        self.public_key_size = 0

        self.private_key_size = 0

        self.ciphertext_size = 0

        self.shared_secret_size = 0

        self.success_count = 0

        self.failure_count = 0

        self.public_key = None

        self.private_key = None

        self.ciphertext = None

        self.shared_secret_sender = None

        self.shared_secret_receiver = None

    # ========================================================
    # Print Header
    # ========================================================

    def print_header(self):

        print("\n" + "=" * 70)

        print("ML-KEM (KYBER) PROFESSIONAL BENCHMARK")

        print("=" * 70)

        print()

        print(f"Iterations : {ITERATIONS}")

        print()
            # ========================================================
    # Benchmark ML-KEM Key Generation
    # ========================================================

    def benchmark_key_generation(self):

        print("Benchmarking ML-KEM Key Generation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            public_key, private_key = (

                kyber.generate_keypair()

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

                private_key

            )

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        self.public_key = public_key

        self.private_key = private_key

        print()

        print("✓ Key Generation Benchmark Completed")

        print()
            # ========================================================
    # Benchmark Encapsulation
    # ========================================================

    def benchmark_encapsulation(self):

        print("Benchmarking ML-KEM Encapsulation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            ciphertext, shared_secret = (

                kyber.encapsulate(

                    self.public_key

                )

            )

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.encapsulation_times.append(

                elapsed

            )

            self.ciphertext_size = len(

                ciphertext

            )

            self.shared_secret_size = len(

                shared_secret

            )

            self.ciphertext = ciphertext

            self.shared_secret_sender = shared_secret

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Encapsulation Benchmark Completed")

        print()
            # ========================================================
    # Benchmark Decapsulation
    # ========================================================

    def benchmark_decapsulation(self):

        print("Benchmarking ML-KEM Decapsulation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            recovered_secret = (

                kyber.decapsulate(

                    self.private_key,

                    self.ciphertext

                )

            )

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.decapsulation_times.append(

                elapsed

            )

            self.shared_secret_receiver = recovered_secret

            if (

                self.shared_secret_sender

                ==

                self.shared_secret_receiver

            ):

                self.success_count += 1

            else:

                self.failure_count += 1

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Decapsulation Benchmark Completed")

        print()

        self.shared_secret_match = (

            self.failure_count == 0

        )
            # ========================================================
    # Export Results to CSV
    # ========================================================

    def export_csv(self):

        csv_file = RESULT_FOLDER / "kyber_results.csv"

        with open(

            csv_file,

            "w",

            newline=""

        ) as file:

            writer = csv.writer(file)

            writer.writerow([

                "Iteration",

                "Key Generation (ms)",

                "Encapsulation (ms)",

                "Decapsulation (ms)"

            ])

            for i in range(ITERATIONS):

                writer.writerow([

                    i + 1,

                    self.keygen_times[i],

                    self.encapsulation_times[i],

                    self.decapsulation_times[i]

                ])

        print()

        print(f"✓ CSV Saved : {csv_file}")

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

        plt.title("ML-KEM Key Generation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "kyber_key_generation.png",

            dpi=300

        )

        plt.close()

        # ----------------------------------------------------
        # Encapsulation Graph
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.encapsulation_times,

            linewidth=2

        )

        plt.title("ML-KEM Encapsulation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "kyber_encapsulation.png",

            dpi=300

        )

        plt.close()

        # ----------------------------------------------------
        # Decapsulation Graph
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.decapsulation_times,

            linewidth=2

        )

        plt.title("ML-KEM Decapsulation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "kyber_decapsulation.png",

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
        print("ML-KEM (KYBER) PROFESSIONAL BENCHMARK REPORT")
        print("=" * 70)

        print(f"\nIterations                : {ITERATIONS}")

        print("\nKEY SIZES")
        print("-" * 70)

        print(f"Public Key Size           : {self.public_key_size} Bytes")
        print(f"Private Key Size          : {self.private_key_size} Bytes")
        print(f"Ciphertext Size           : {self.ciphertext_size} Bytes")
        print(f"Shared Secret Size        : {self.shared_secret_size} Bytes")

        print("\nKEY GENERATION")
        print("-" * 70)

        print(f"Average                   : {statistics.mean(self.keygen_times):.3f} ms")
        print(f"Minimum                   : {min(self.keygen_times):.3f} ms")
        print(f"Maximum                   : {max(self.keygen_times):.3f} ms")
        print(f"Std. Deviation            : {statistics.stdev(self.keygen_times):.3f} ms")

        print("\nENCAPSULATION")
        print("-" * 70)

        print(f"Average                   : {statistics.mean(self.encapsulation_times):.3f} ms")
        print(f"Minimum                   : {min(self.encapsulation_times):.3f} ms")
        print(f"Maximum                   : {max(self.encapsulation_times):.3f} ms")
        print(f"Std. Deviation            : {statistics.stdev(self.encapsulation_times):.3f} ms")

        print("\nDECAPSULATION")
        print("-" * 70)

        print(f"Average                   : {statistics.mean(self.decapsulation_times):.3f} ms")
        print(f"Minimum                   : {min(self.decapsulation_times):.3f} ms")
        print(f"Maximum                   : {max(self.decapsulation_times):.3f} ms")
        print(f"Std. Deviation            : {statistics.stdev(self.decapsulation_times):.3f} ms")

        keygen_tp = 1000 / statistics.mean(self.keygen_times)
        encaps_tp = 1000 / statistics.mean(self.encapsulation_times)
        decaps_tp = 1000 / statistics.mean(self.decapsulation_times)

        print("\nTHROUGHPUT")
        print("-" * 70)

        print(f"Key Generation Throughput : {keygen_tp:.2f} operations/sec")
        print(f"Encapsulation Throughput  : {encaps_tp:.2f} operations/sec")
        print(f"Decapsulation Throughput  : {decaps_tp:.2f} operations/sec")

        print("\nRESULT")
        print("-" * 70)

        print(f"Successful Matches        : {self.success_count}")
        print(f"Failed Matches            : {self.failure_count}")

        print(
            f"Shared Secret Match       : "
            f"{'TRUE' if self.shared_secret_match else 'FALSE'}"
        )

        print(
            f"Success Rate              : "
            f"{(self.success_count / ITERATIONS) * 100:.2f}%"
        )

        print("=" * 70)
        # ============================================================
# Main
# ============================================================

def main():

    benchmark = KyberBenchmark()

    benchmark.print_header()

    benchmark.benchmark_key_generation()

    benchmark.benchmark_encapsulation()

    benchmark.benchmark_decapsulation()

    benchmark.export_csv()

    benchmark.generate_graphs()

    benchmark.display_report()


if __name__ == "__main__":

    main()