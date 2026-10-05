"""
PQC-VANET Cryptographic Timing Experiment
-----------------------------------------

Benchmarks the ACTUAL cryptographic primitives used by the project:

ML-DSA-65:
    - Key Generation
    - Signing
    - Verification

ML-KEM-768:
    - Key Generation
    - Encapsulation
    - Decapsulation

This file DOES NOT modify any project source code.

It only imports and calls the existing functions from:
    crypto/dilithium.py
    crypto/kyber.py

Outputs:
    results/crypto_timing_raw.csv
    results/crypto_timing_summary.csv
"""

import argparse
import csv
import statistics
import time
from pathlib import Path

from crypto import dilithium
from crypto import kyber


# ============================================================
# Configuration
# ============================================================

RESULTS_DIR = Path("results")

RAW_CSV = RESULTS_DIR / "crypto_timing_raw.csv"
SUMMARY_CSV = RESULTS_DIR / "crypto_timing_summary.csv"

DEFAULT_WARMUP = 50
DEFAULT_RUNS = 1000


# ============================================================
# Timing helper
# ============================================================

def measure_operation(operation, function, runs):
    """
    Measure one cryptographic operation repeatedly.

    Returns:
        List of elapsed times in milliseconds.
    """

    times_ms = []

    for _ in range(runs):

        start = time.perf_counter_ns()

        function()

        end = time.perf_counter_ns()

        elapsed_ms = (end - start) / 1_000_000

        times_ms.append(elapsed_ms)

    return times_ms


# ============================================================
# Statistics helper
# ============================================================

def calculate_statistics(values):

    return {
        "mean_ms": statistics.mean(values),
        "std_ms": (
            statistics.stdev(values)
            if len(values) > 1
            else 0.0
        ),
        "min_ms": min(values),
        "max_ms": max(values),
    }


# ============================================================
# ML-DSA benchmark
# ============================================================

def benchmark_mldsa(warmup, runs):

    print()
    print("=" * 70)
    print("ML-DSA-65 TIMING")
    print("=" * 70)

    raw_results = []
    summary_results = []

    message = (
        b"PQC-VANET ML-DSA-65 cryptographic timing benchmark "
        b"message"
    )

    # --------------------------------------------------------
    # ML-DSA Key Generation
    # --------------------------------------------------------

    print("\n[1/3] ML-DSA Key Generation")

    for _ in range(warmup):
        dilithium.generate_keypair()

    keygen_times = measure_operation(
        "ML-DSA Key Generation",
        dilithium.generate_keypair,
        runs
    )

    stats = calculate_statistics(keygen_times)

    print(
        f"Mean : {stats['mean_ms']:.6f} ms"
    )
    print(
        f"Std  : {stats['std_ms']:.6f} ms"
    )
    print(
        f"Min  : {stats['min_ms']:.6f} ms"
    )
    print(
        f"Max  : {stats['max_ms']:.6f} ms"
    )

    for i, value in enumerate(keygen_times, 1):
        raw_results.append({
            "primitive": "ML-DSA-65",
            "operation": "Key Generation",
            "run": i,
            "time_ms": value
        })

    summary_results.append({
        "primitive": "ML-DSA-65",
        "operation": "Key Generation",
        **stats
    })

    # --------------------------------------------------------
    # Generate one key pair for signing/verification
    # --------------------------------------------------------

    sig_pk, sig_sk = dilithium.generate_keypair()

    # --------------------------------------------------------
    # ML-DSA Signing
    # --------------------------------------------------------

    print("\n[2/3] ML-DSA Signing")

    for _ in range(warmup):
        dilithium.sign_message(
            sig_sk,
            message
        )

    sign_times = measure_operation(
        "ML-DSA Signing",
        lambda: dilithium.sign_message(
            sig_sk,
            message
        ),
        runs
    )

    stats = calculate_statistics(sign_times)

    print(
        f"Mean : {stats['mean_ms']:.6f} ms"
    )
    print(
        f"Std  : {stats['std_ms']:.6f} ms"
    )
    print(
        f"Min  : {stats['min_ms']:.6f} ms"
    )
    print(
        f"Max  : {stats['max_ms']:.6f} ms"
    )

    for i, value in enumerate(sign_times, 1):
        raw_results.append({
            "primitive": "ML-DSA-65",
            "operation": "Signing",
            "run": i,
            "time_ms": value
        })

    summary_results.append({
        "primitive": "ML-DSA-65",
        "operation": "Signing",
        **stats
    })

    # --------------------------------------------------------
    # Create valid signature for verification benchmark
    # --------------------------------------------------------

    signature = dilithium.sign_message(
        sig_sk,
        message
    )

    # --------------------------------------------------------
    # ML-DSA Verification
    # --------------------------------------------------------

    print("\n[3/3] ML-DSA Verification")

    for _ in range(warmup):

        valid = dilithium.verify_signature(
            sig_pk,
            message,
            signature
        )

        if not valid:
            raise RuntimeError(
                "ML-DSA verification failed during warm-up."
            )

    def verify_operation():

        valid = dilithium.verify_signature(
            sig_pk,
            message,
            signature
        )

        if not valid:
            raise RuntimeError(
                "ML-DSA verification unexpectedly failed."
            )

    verify_times = measure_operation(
        "ML-DSA Verification",
        verify_operation,
        runs
    )

    stats = calculate_statistics(verify_times)

    print(
        f"Mean : {stats['mean_ms']:.6f} ms"
    )
    print(
        f"Std  : {stats['std_ms']:.6f} ms"
    )
    print(
        f"Min  : {stats['min_ms']:.6f} ms"
    )
    print(
        f"Max  : {stats['max_ms']:.6f} ms"
    )

    for i, value in enumerate(verify_times, 1):
        raw_results.append({
            "primitive": "ML-DSA-65",
            "operation": "Verification",
            "run": i,
            "time_ms": value
        })

    summary_results.append({
        "primitive": "ML-DSA-65",
        "operation": "Verification",
        **stats
    })

    return raw_results, summary_results


# ============================================================
# ML-KEM benchmark
# ============================================================

def benchmark_mlkem(warmup, runs):

    print()
    print("=" * 70)
    print("ML-KEM-768 TIMING")
    print("=" * 70)

    raw_results = []
    summary_results = []

    # --------------------------------------------------------
    # ML-KEM Key Generation
    # --------------------------------------------------------

    print("\n[1/3] ML-KEM Key Generation")

    for _ in range(warmup):
        kyber.generate_keypair()

    keygen_times = measure_operation(
        "ML-KEM Key Generation",
        kyber.generate_keypair,
        runs
    )

    stats = calculate_statistics(keygen_times)

    print(
        f"Mean : {stats['mean_ms']:.6f} ms"
    )
    print(
        f"Std  : {stats['std_ms']:.6f} ms"
    )
    print(
        f"Min  : {stats['min_ms']:.6f} ms"
    )
    print(
        f"Max  : {stats['max_ms']:.6f} ms"
    )

    for i, value in enumerate(keygen_times, 1):
        raw_results.append({
            "primitive": "ML-KEM-768",
            "operation": "Key Generation",
            "run": i,
            "time_ms": value
        })

    summary_results.append({
        "primitive": "ML-KEM-768",
        "operation": "Key Generation",
        **stats
    })

    # --------------------------------------------------------
    # Generate key pair for encapsulation/decapsulation
    # --------------------------------------------------------

    kem_pk, kem_sk = kyber.generate_keypair()

    # --------------------------------------------------------
    # ML-KEM Encapsulation
    # --------------------------------------------------------

    print("\n[2/3] ML-KEM Encapsulation")

    for _ in range(warmup):

        ciphertext, shared_secret = kyber.encapsulate(
            kem_pk
        )

        if not ciphertext or not shared_secret:
            raise RuntimeError(
                "ML-KEM encapsulation failed during warm-up."
            )

    def encapsulate_operation():

        ciphertext, shared_secret = kyber.encapsulate(
            kem_pk
        )

        if not ciphertext or not shared_secret:
            raise RuntimeError(
                "ML-KEM encapsulation unexpectedly failed."
            )

    encapsulate_times = measure_operation(
        "ML-KEM Encapsulation",
        encapsulate_operation,
        runs
    )

    stats = calculate_statistics(encapsulate_times)

    print(
        f"Mean : {stats['mean_ms']:.6f} ms"
    )
    print(
        f"Std  : {stats['std_ms']:.6f} ms"
    )
    print(
        f"Min  : {stats['min_ms']:.6f} ms"
    )
    print(
        f"Max  : {stats['max_ms']:.6f} ms"
    )

    for i, value in enumerate(encapsulate_times, 1):
        raw_results.append({
            "primitive": "ML-KEM-768",
            "operation": "Encapsulation",
            "run": i,
            "time_ms": value
        })

    summary_results.append({
        "primitive": "ML-KEM-768",
        "operation": "Encapsulation",
        **stats
    })

    # --------------------------------------------------------
    # Generate valid ciphertext for decapsulation
    # --------------------------------------------------------

    ciphertext, sender_shared_secret = kyber.encapsulate(
        kem_pk
    )

    # --------------------------------------------------------
    # ML-KEM Decapsulation
    # --------------------------------------------------------

    print("\n[3/3] ML-KEM Decapsulation")

    for _ in range(warmup):

        receiver_shared_secret = kyber.decapsulate(
            kem_sk,
            ciphertext
        )

        if receiver_shared_secret != sender_shared_secret:
            raise RuntimeError(
                "ML-KEM decapsulation shared-secret mismatch "
                "during warm-up."
            )

    def decapsulate_operation():

        receiver_shared_secret = kyber.decapsulate(
            kem_sk,
            ciphertext
        )

        if receiver_shared_secret != sender_shared_secret:
            raise RuntimeError(
                "ML-KEM decapsulation shared-secret mismatch."
            )

    decapsulate_times = measure_operation(
        "ML-KEM Decapsulation",
        decapsulate_operation,
        runs
    )

    stats = calculate_statistics(decapsulate_times)

    print(
        f"Mean : {stats['mean_ms']:.6f} ms"
    )
    print(
        f"Std  : {stats['std_ms']:.6f} ms"
    )
    print(
        f"Min  : {stats['min_ms']:.6f} ms"
    )
    print(
        f"Max  : {stats['max_ms']:.6f} ms"
    )

    for i, value in enumerate(decapsulate_times, 1):
        raw_results.append({
            "primitive": "ML-KEM-768",
            "operation": "Decapsulation",
            "run": i,
            "time_ms": value
        })

    summary_results.append({
        "primitive": "ML-KEM-768",
        "operation": "Decapsulation",
        **stats
    })

    return raw_results, summary_results


# ============================================================
# Save CSV files
# ============================================================

def save_results(raw_results, summary_results):

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Raw results
    # --------------------------------------------------------

    with open(
        RAW_CSV,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "primitive",
                "operation",
                "run",
                "time_ms"
            ]
        )

        writer.writeheader()
        writer.writerows(raw_results)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    with open(
        SUMMARY_CSV,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "primitive",
                "operation",
                "mean_ms",
                "std_ms",
                "min_ms",
                "max_ms"
            ]
        )

        writer.writeheader()
        writer.writerows(summary_results)


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "PQC-VANET ML-DSA-65 and ML-KEM-768 "
            "cryptographic timing benchmark."
        )
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS
    )

    args = parser.parse_args()

    if args.warmup < 0:
        raise ValueError(
            "warmup must be zero or greater."
        )

    if args.runs < 1:
        raise ValueError(
            "runs must be at least 1."
        )

    print()
    print("=" * 70)
    print("PQC-VANET CRYPTOGRAPHIC TIMING EXPERIMENT")
    print("=" * 70)
    print()
    print("ML-DSA : ML-DSA-65")
    print("ML-KEM : ML-KEM-768")
    print(f"Warm-up runs : {args.warmup}")
    print(f"Measured runs: {args.runs}")
    print()
    print("No project source files are modified.")
    print("=" * 70)

    # --------------------------------------------------------
    # ML-DSA
    # --------------------------------------------------------

    mldsa_raw, mldsa_summary = benchmark_mldsa(
        args.warmup,
        args.runs
    )

    # --------------------------------------------------------
    # ML-KEM
    # --------------------------------------------------------

    mlkem_raw, mlkem_summary = benchmark_mlkem(
        args.warmup,
        args.runs
    )

    # --------------------------------------------------------
    # Combine results
    # --------------------------------------------------------

    raw_results = (
        mldsa_raw +
        mlkem_raw
    )

    summary_results = (
        mldsa_summary +
        mlkem_summary
    )

    save_results(
        raw_results,
        summary_results
    )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("FINAL CRYPTOGRAPHIC TIMING SUMMARY")
    print("=" * 70)

    for result in summary_results:

        print(
            f"{result['primitive']:12s} | "
            f"{result['operation']:15s} | "
            f"Mean = {result['mean_ms']:.6f} ms | "
            f"SD = {result['std_ms']:.6f} ms"
        )

    print()
    print(f"Raw results     : {RAW_CSV}")
    print(f"Summary results : {SUMMARY_CSV}")
    print("=" * 70)
    print("CRYPTOGRAPHIC TIMING EXPERIMENT COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()