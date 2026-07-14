"""
=============================================================
QRNG Professional Benchmark Suite
-------------------------------------------------------------
Research Version 2.0

Features
--------
• Random Byte Generation
• Nonce Generation
• Secret Value Generation
• CSV Export
• Graph Generation
• Throughput
• Statistics

Author : Meeth Amin
=============================================================
"""

import csv
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

from crypto import qrng


ITERATIONS = 100


RESULT_FOLDER = CURRENT_DIR / "benchmark_results"

RESULT_FOLDER.mkdir(exist_ok=True)
# ============================================================
# QRNG Benchmark Class
# ============================================================

class QRNGBenchmark:

    def __init__(self):

        self.random_times = []

        self.nonce_times = []

        self.secret_times = []

        self.random_size = 0

        self.nonce_size = 0

        self.secret_size = 0

        self.success_count = 0

        self.failure_count = 0

    # ========================================================
    # Print Header
    # ========================================================

    def print_header(self):

        print("\n" + "=" * 70)

        print("QRNG PROFESSIONAL BENCHMARK")

        print("=" * 70)

        print()

        print(f"Iterations : {ITERATIONS}")

        print()
            # ========================================================
    # Benchmark Random Byte Generation
    # ========================================================

    def benchmark_random_bytes(self):

        print("Benchmarking Random Byte Generation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            rnd = qrng.generate_random_bytes(32)

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.random_times.append(

                elapsed

            )

            self.random_size = len(

                rnd

            )

            if rnd:

                self.success_count += 1

            else:

                self.failure_count += 1

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Random Byte Benchmark Completed")

        print()
            # ========================================================
    # Benchmark Nonce Generation
    # ========================================================

    def benchmark_nonce_generation(self):

        print("Benchmarking Nonce Generation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            nonce = qrng.generate_nonce()

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.nonce_times.append(

                elapsed

            )

            self.nonce_size = len(

                nonce

            )

            if nonce:

                self.success_count += 1

            else:

                self.failure_count += 1

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Nonce Generation Benchmark Completed")

        print()
            # ========================================================
    # Benchmark Secret Value Generation
    # ========================================================

    def benchmark_secret_generation(self):

        print("Benchmarking Secret Value Generation...")

        print("-" * 70)

        for i in range(ITERATIONS):

            start = time.perf_counter()

            secret = qrng.generate_secret_value()

            elapsed = (

                time.perf_counter()

                - start

            ) * 1000

            self.secret_times.append(

                elapsed

            )

            self.secret_size = len(

                secret

            )

            if secret:

                self.success_count += 1

            else:

                self.failure_count += 1

            if (i + 1) % 20 == 0:

                print(

                    f"Completed {i + 1}/{ITERATIONS}"

                )

        print()

        print("✓ Secret Value Benchmark Completed")

        print()
            # ========================================================
    # Export Results to CSV
    # ========================================================

    def export_csv(self):

        csv_file = RESULT_FOLDER / "qrng_results.csv"

        with open(

            csv_file,

            "w",

            newline=""

        ) as file:

            writer = csv.writer(file)

            writer.writerow([

                "Iteration",

                "Random Bytes (ms)",

                "Nonce Generation (ms)",

                "Secret Value Generation (ms)"

            ])

            for i in range(ITERATIONS):

                writer.writerow([

                    i + 1,

                    self.random_times[i],

                    self.nonce_times[i],

                    self.secret_times[i]

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
        # Random Byte Generation
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.random_times,

            linewidth=2

        )

        plt.title("QRNG Random Byte Generation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "qrng_random_bytes.png",

            dpi=300

        )

        plt.close()

        # ----------------------------------------------------
        # Nonce Generation
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.nonce_times,

            linewidth=2

        )

        plt.title("QRNG Nonce Generation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "qrng_nonce_generation.png",

            dpi=300

        )

        plt.close()

        # ----------------------------------------------------
        # Secret Value Generation
        # ----------------------------------------------------

        plt.figure(figsize=(10, 5))

        plt.plot(

            range(1, ITERATIONS + 1),

            self.secret_times,

            linewidth=2

        )

        plt.title("QRNG Secret Value Generation Time")

        plt.xlabel("Iteration")

        plt.ylabel("Time (ms)")

        plt.grid(True)

        plt.tight_layout()

        plt.savefig(

            RESULT_FOLDER / "qrng_secret_generation.png",

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
        print("QRNG PROFESSIONAL BENCHMARK REPORT")
        print("=" * 70)

        print(f"\nIterations                : {ITERATIONS}")

        print("\nOUTPUT SIZES")
        print("-" * 70)

        print(f"Random Bytes Size         : {self.random_size} Bytes")
        print(f"Nonce Size               : {self.nonce_size} Bytes")
        print(f"Secret Value Size        : {self.secret_size} Bytes")

        print("\nRANDOM BYTE GENERATION")
        print("-" * 70)

        print(f"Average                  : {statistics.mean(self.random_times):.3f} ms")
        print(f"Minimum                  : {min(self.random_times):.3f} ms")
        print(f"Maximum                  : {max(self.random_times):.3f} ms")
        print(f"Std. Deviation           : {statistics.stdev(self.random_times):.3f} ms")

        print("\nNONCE GENERATION")
        print("-" * 70)

        print(f"Average                  : {statistics.mean(self.nonce_times):.3f} ms")
        print(f"Minimum                  : {min(self.nonce_times):.3f} ms")
        print(f"Maximum                  : {max(self.nonce_times):.3f} ms")
        print(f"Std. Deviation           : {statistics.stdev(self.nonce_times):.3f} ms")

        print("\nSECRET VALUE GENERATION")
        print("-" * 70)

        print(f"Average                  : {statistics.mean(self.secret_times):.3f} ms")
        print(f"Minimum                  : {min(self.secret_times):.3f} ms")
        print(f"Maximum                  : {max(self.secret_times):.3f} ms")
        print(f"Std. Deviation           : {statistics.stdev(self.secret_times):.3f} ms")

        random_tp = 1000 / statistics.mean(self.random_times)
        nonce_tp = 1000 / statistics.mean(self.nonce_times)
        secret_tp = 1000 / statistics.mean(self.secret_times)

        print("\nTHROUGHPUT")
        print("-" * 70)

        print(f"Random Byte Throughput   : {random_tp:.2f} operations/sec")
        print(f"Nonce Throughput         : {nonce_tp:.2f} operations/sec")
        print(f"Secret Throughput        : {secret_tp:.2f} operations/sec")

        total_success = self.success_count
        total_failure = self.failure_count
        total_operations = total_success + total_failure

        success_rate = (
            (total_success / total_operations) * 100
            if total_operations > 0 else 0
        )

        print("\nRESULT")
        print("-" * 70)

        print(f"Successful Operations    : {total_success}")
        print(f"Failed Operations        : {total_failure}")
        print(f"Success Rate             : {success_rate:.2f}%")

        print("=" * 70)
        # ============================================================
# Main
# ============================================================

def main():

    benchmark = QRNGBenchmark()

    benchmark.print_header()

    benchmark.benchmark_random_bytes()

    benchmark.benchmark_nonce_generation()

    benchmark.benchmark_secret_generation()

    benchmark.export_csv()

    benchmark.generate_graphs()

    benchmark.display_report()


if __name__ == "__main__":

    main()