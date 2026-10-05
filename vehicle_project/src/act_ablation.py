"""
ACT Ablation Experiment for PQC-VANET
-------------------------------------
Compares:

A) Baseline: freshness/context -> ML-DSA -> ML-KEM -> M4
   (ACT is removed from the admission path)

B) Proposed: ACT -> freshness/context -> ML-DSA -> ML-KEM -> M4
   (uses the implemented ACT pre-filter)

The experiment uses the CURRENT M1-M4 implementation without editing
mutual_authentication.py.

Attack workload:
    invalid ACT + valid ML-DSA signature

This is intentional: the baseline ignores ACT, so the request reaches
ML-DSA and then ML-KEM. The proposed protocol rejects it at ACT.

Outputs:
    results/act_ablation_raw.csv
    results/act_ablation_summary.csv

Quick test:
    python act_ablation.py --trials 2 --requests 20

Paper-scale run:
    python act_ablation.py --trials 10 --requests 1000
"""

import argparse
import contextlib
import csv
import io
import math
import os
import random
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

from crypto import dilithium
from crypto import kyber
from models.trusted_authority import TrustedAuthority
from models.rsu import RSU
from models.vehicle import Vehicle
from certificateless_key_generation import CertificatelessKeyGeneration
from pseudonym_genration import PseudonymGeneration
from mutual_authentication import MutualAuthentication


TRAFFIC_LEVELS = (0, 10, 20, 40, 60, 80, 90)
DEFAULT_TRIALS = 3
DEFAULT_REQUESTS = 100

RESULTS_DIR = Path("results")
RAW_CSV = RESULTS_DIR / "act_ablation_raw.csv"
SUMMARY_CSV = RESULTS_DIR / "act_ablation_summary.csv"


@dataclass
class CryptoCounts:
    mldsa_verify: int = 0
    kem_keygen: int = 0
    kem_encapsulate: int = 0
    kem_decapsulate: int = 0

    @property
    def kem_total(self):
        return (
            self.kem_keygen
            + self.kem_encapsulate
            + self.kem_decapsulate
        )


class CryptoCounterPatch:
    """Temporarily wraps the real PQC functions and counts calls."""

    def __init__(self, counts):
        self.counts = counts
        self.originals = {}

    def __enter__(self):
        self.originals["verify_signature"] = dilithium.verify_signature
        self.originals["generate_keypair"] = kyber.generate_keypair
        self.originals["encapsulate"] = kyber.encapsulate
        self.originals["decapsulate"] = kyber.decapsulate

        original_verify = self.originals["verify_signature"]
        original_keygen = self.originals["generate_keypair"]
        original_encapsulate = self.originals["encapsulate"]
        original_decapsulate = self.originals["decapsulate"]

        def counted_verify(*args, **kwargs):
            self.counts.mldsa_verify += 1
            return original_verify(*args, **kwargs)

        def counted_keygen(*args, **kwargs):
            self.counts.kem_keygen += 1
            return original_keygen(*args, **kwargs)

        def counted_encapsulate(*args, **kwargs):
            self.counts.kem_encapsulate += 1
            return original_encapsulate(*args, **kwargs)

        def counted_decapsulate(*args, **kwargs):
            self.counts.kem_decapsulate += 1
            return original_decapsulate(*args, **kwargs)

        dilithium.verify_signature = counted_verify
        kyber.generate_keypair = counted_keygen
        kyber.encapsulate = counted_encapsulate
        kyber.decapsulate = counted_decapsulate

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        dilithium.verify_signature = self.originals["verify_signature"]
        kyber.generate_keypair = self.originals["generate_keypair"]
        kyber.encapsulate = self.originals["encapsulate"]
        kyber.decapsulate = self.originals["decapsulate"]


def quiet_call(function, *args, **kwargs):
    """Run protocol functions without flooding the terminal."""
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args, **kwargs)


def build_environment(scenario):
    """
    Build the same registration/key/pseudonym stack used by main.py.

    Returns:
        ta, sender, responder
    """
    ta = TrustedAuthority()

    sender = Vehicle(
        real_id="VEHICLE001",
        trusted_authority=ta,
    )

    if scenario == "v2v":
        responder = Vehicle(
            real_id="VEHICLE002",
            trusted_authority=ta,
        )
    elif scenario == "v2i":
        responder = RSU(
            rsu_id="RSU001",
            trusted_authority=ta,
        )
    else:
        raise ValueError("scenario must be 'v2v' or 'v2i'")

    # RSU initialization follows the project's main.py.
    if isinstance(responder, RSU):
        ta.register_rsu(responder)
        responder.register()
        responder.initialize_crypto()

    # Vehicle registration follows the project's main.py.
    ta.register_vehicle(sender)

    if isinstance(responder, Vehicle):
        ta.register_vehicle(responder)

    # Certificateless key generation follows the project.
    key_generator = CertificatelessKeyGeneration(ta)
    key_generator.generate_keys_for_all(
        [sender] + ([responder] if isinstance(responder, Vehicle) else [])
    )
    key_generator.verify_all(
        [sender] + ([responder] if isinstance(responder, Vehicle) else [])
    )

    # Adaptive pseudonym generation follows the project.
    pseudonym_manager = PseudonymGeneration(ta)
    pseudonym_manager.generate_for_all(
        [sender] + ([responder] if isinstance(responder, Vehicle) else [])
    )
    pseudonym_manager.verify_all(
        [sender] + ([responder] if isinstance(responder, Vehicle) else [])
    )

    return ta, sender, responder


def make_invalid_act_request(generator, sender, responder):
    """
    Create a request whose ACT is invalid but whose ML-DSA signature is valid.

    This is the key controlled workload for the ACT ablation:
    - Proposed system: rejects at ACT.
    - Baseline: ignores ACT and therefore reaches ML-DSA and ML-KEM.
    """
    request = quiet_call(
        generator.create_auth_request,
        sender,
        responder,
    )

    bad_act = "0" * 64

    signed_data = generator._m1_signed_data(
        request["sender_pseudonym"],
        request["receiver"],
        request["timestamp"],
        request["nonce"],
        request["road_segment"],
        request["vehicle_state"],
        bad_act,
    )

    request["act"] = bad_act
    request["signature"] = dilithium.sign_message(
        sender.sig_sk,
        signed_data,
    )

    return request


def make_request(generator, sender, responder, malicious):
    if malicious:
        return make_invalid_act_request(
            generator,
            sender,
            responder,
        )

    return quiet_call(
        generator.create_auth_request,
        sender,
        responder,
    )


def verify_m1_without_act(manager, receiver, request):
    """
    Baseline M1 verification.

    This is deliberately the same common logic as the current
    verify_auth_request(), except the ACT gate is removed.

    Order:
        structure -> receiver -> freshness -> replay ->
        pseudonym lookup -> revocation -> context -> ML-DSA

    No ACT verification is performed.
    """
    required_fields = {
        "sender_pseudonym",
        "receiver",
        "timestamp",
        "nonce",
        "road_segment",
        "vehicle_state",
        "act",
        "signature",
    }

    if not required_fields.issubset(request.keys()):
        return False

    expected_receiver = manager._identity(receiver)

    if request["receiver"] != expected_receiver:
        return False

    current_time = int(time.time())

    if abs(current_time - request["timestamp"]) > manager.timestamp_window:
        return False

    nonce_hex = request["nonce"].hex()

    if nonce_hex in manager.used_nonces:
        return False

    sender = manager.ta.get_vehicle_by_pseudonym(
        request["sender_pseudonym"]
    )

    if sender is None:
        return False

    if manager.ta.is_revoked(sender.real_id):
        return False

    allowed_states = ("ACTIVE", "EMERGENCY")
    if request["vehicle_state"] not in allowed_states:
        return False

    allowed_segments = (
        "RS-001",
        "NH66",
        "CITY_ZONE",
        "MILITARY_ZONE",
    )
    if request["road_segment"] not in allowed_segments:
        return False

    message = manager._m1_signed_data(
        request["sender_pseudonym"],
        expected_receiver,
        request["timestamp"],
        request["nonce"],
        request["road_segment"],
        request["vehicle_state"],
        request["act"],
    )

    if not dilithium.verify_signature(
        sender.sig_pk,
        message,
        request["signature"],
    ):
        return False

    manager.used_nonces.add(nonce_hex)
    return True


def run_after_m1(manager, sender, responder, request):
    """Run the same M2-M4 path used by authenticate()."""

    response = quiet_call(
        manager.create_auth_response,
        responder,
        sender,
    )

    if not quiet_call(
        manager.verify_auth_response,
        sender,
        responder,
        response,
    ):
        return False

    m3_state = quiet_call(
        manager.create_m3_kem_message,
        sender,
        responder,
        request,
        response,
    )

    if m3_state is None:
        return False

    sender_shared_secret = m3_state["shared_secret"]
    m3 = m3_state["m3"]

    responder_session_key = quiet_call(
        manager.process_m3_kem_message,
        sender,
        responder,
        request,
        response,
        m3,
    )

    response.pop("_ephemeral_kem_sk", None)

    if responder_session_key is None:
        return False

    sender_session_key = quiet_call(
        manager._derive_context_key,
        sender_shared_secret,
        request,
        response,
    )

    if sender_session_key is None:
        return False

    if not quiet_call(
        manager.context_key_manager.verify_session_key,
        sender_session_key,
    ):
        return False

    if not __import__("hmac").compare_digest(
        sender_session_key,
        responder_session_key,
    ):
        return False

    m4 = quiet_call(
        manager.create_m4_confirmation,
        responder,
        sender,
        request,
        response,
        responder_session_key,
    )

    if not quiet_call(
        manager.verify_m4_confirmation,
        sender,
        responder,
        request,
        response,
        sender_session_key,
        m4,
    ):
        return False

    # Keep the same session record semantics as authenticate().
    quiet_call(
        manager._store_session,
        sender,
        responder,
        sender_session_key,
        m3["ciphertext"],
        request,
        response,
    )

    return True


def process_one(manager, sender, responder, request, use_act):
    """
    Process one already-created M1.

    Timing begins at M1 receiver processing and ends after M4.
    M1 creation/signing is intentionally outside the measured time.
    """
    start = time.perf_counter()

    if use_act:
        m1_ok = quiet_call(
            manager.verify_auth_request,
            responder,
            request,
        )
    else:
        m1_ok = quiet_call(
            verify_m1_without_act,
            manager,
            responder,
            request,
        )

    if not m1_ok:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, True

    success = run_after_m1(
        manager,
        sender,
        responder,
        request,
    )

    elapsed = (time.perf_counter() - start) * 1000
    return success, elapsed, not success


def run_batch(manager, sender, responder, requests, use_act):
    """Run one complete workload and return measured metrics."""
    counts = CryptoCounts()
    times = []
    rejection_times = []
    successful = 0
    rejected = 0

    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    with CryptoCounterPatch(counts):
        for request, malicious in requests:
            success, elapsed, was_rejected = process_one(
                manager,
                sender,
                responder,
                request,
                use_act,
            )

            times.append(elapsed)

            if success:
                successful += 1

            if was_rejected:
                rejected += 1
                rejection_times.append(elapsed)

    wall_elapsed = time.perf_counter() - wall_start
    cpu_elapsed = time.process_time() - cpu_start

    total_time_ms = sum(times)
    average_time_ms = (
        total_time_ms / len(times)
        if times
        else 0.0
    )

    throughput = (
        len(requests) / wall_elapsed
        if wall_elapsed > 0
        else 0.0
    )

    process_cpu_percent = (
        (cpu_elapsed / wall_elapsed) * 100.0
        if wall_elapsed > 0
        else 0.0
    )

    average_rejection_latency = (
        statistics.mean(rejection_times)
        if rejection_times
        else math.nan
    )

    malicious_count = sum(1 for _, malicious in requests if malicious)
    valid_count = len(requests) - malicious_count

    return {
        "total_time_ms": total_time_ms,
        "average_time_ms": average_time_ms,
        "successful": successful,
        "rejected": rejected,
        "rejection_latency_ms": average_rejection_latency,
        "throughput": throughput,
        "process_cpu_percent": process_cpu_percent,
        "mldsa_verify": counts.mldsa_verify,
        "kem_keygen": counts.kem_keygen,
        "kem_encapsulate": counts.kem_encapsulate,
        "kem_decapsulate": counts.kem_decapsulate,
        "kem_total": counts.kem_total,
        "malicious": malicious_count,
        "valid": valid_count,
    }


def percent_avoided(baseline, proposed):
    if baseline <= 0:
        return 0.0
    return ((baseline - proposed) / baseline) * 100.0


def generate_workload(generator, sender, responder, total_requests, malicious_rate, seed):
    """
    Generate one identical workload for both baseline and ACT runs.

    The same M1 packet is sent to both managers, so the comparison is paired.
    """
    rng = random.Random(seed)

    malicious_count = round(
        total_requests * malicious_rate / 100.0
    )

    labels = (
        [True] * malicious_count
        + [False] * (total_requests - malicious_count)
    )
    rng.shuffle(labels)

    workload = []

    for malicious in labels:
        request = make_request(
            generator,
            sender,
            responder,
            malicious,
        )
        workload.append((request, malicious))

    return workload


def warm_up(ta, sender, responder):
    """Small unmeasured warm-up to reduce first-call effects."""
    generator = MutualAuthentication(ta)
    manager = MutualAuthentication(ta)

    for _ in range(2):
        request = quiet_call(
            generator.create_auth_request,
            sender,
            responder,
        )
        quiet_call(
            manager.verify_auth_request,
            responder,
            request,
        )

        # Warm the expensive full path as well.
        request = quiet_call(
            generator.create_auth_request,
            sender,
            responder,
        )
        run_after_m1(
            manager,
            sender,
            responder,
            request,
        )


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


def summarize(raw_rows):
    summary_rows = []

    metric_names = [
        "baseline_average_time_ms",
        "act_average_time_ms",
        "baseline_total_time_ms",
        "act_total_time_ms",
        "baseline_mldsa_verify",
        "act_mldsa_verify",
        "baseline_kem_total",
        "act_kem_total",
        "baseline_kem_keygen",
        "act_kem_keygen",
        "baseline_kem_encapsulate",
        "act_kem_encapsulate",
        "baseline_kem_decapsulate",
        "act_kem_decapsulate",
        "baseline_rejected",
        "act_rejected",
        "baseline_throughput",
        "act_throughput",
        "baseline_process_cpu_percent",
        "act_process_cpu_percent",
        "mldsa_avoided_percent",
        "kem_avoided_percent",
    ]

    grouped = {}

    for row in raw_rows:
        key = (
            row["scenario"],
            int(row["malicious_percent"]),
        )
        grouped.setdefault(key, []).append(row)

    for (scenario, malicious_percent), rows in grouped.items():
        out = {
            "scenario": scenario,
            "malicious_percent": malicious_percent,
            "trials": len(rows),
            "requests_per_trial": rows[0]["total_requests"],
        }

        for metric in metric_names:
            values = [
                float(row[metric])
                for row in rows
            ]

            out[f"{metric}_mean"] = statistics.mean(values)

            out[f"{metric}_std"] = (
                statistics.stdev(values)
                if len(values) > 1
                else 0.0
            )

        baseline_rejection = [
            float(row["baseline_rejection_latency_ms"])
            for row in rows
            if row["baseline_rejection_latency_ms"] != ""
        ]

        act_rejection = [
            float(row["act_rejection_latency_ms"])
            for row in rows
            if row["act_rejection_latency_ms"] != ""
        ]

        out["baseline_rejection_latency_ms_mean"] = (
            statistics.mean(baseline_rejection)
            if baseline_rejection
            else ""
        )

        out["baseline_rejection_latency_ms_std"] = (
            statistics.stdev(baseline_rejection)
            if len(baseline_rejection) > 1
            else (0.0 if baseline_rejection else "")
        )

        out["act_rejection_latency_ms_mean"] = (
            statistics.mean(act_rejection)
            if act_rejection
            else ""
        )

        out["act_rejection_latency_ms_std"] = (
            statistics.stdev(act_rejection)
            if len(act_rejection) > 1
            else (0.0 if act_rejection else "")
        )

        summary_rows.append(out)

    return summary_rows


def run_experiment(trials, requests_per_trial, scenarios):
    raw_rows = []

    for scenario in scenarios:
        print()
        print("=" * 78)
        print(f"ACT ABLATION : {scenario.upper()}")
        print("=" * 78)

        for malicious_percent in TRAFFIC_LEVELS:
            for trial in range(1, trials + 1):
                print(
                    f"[{scenario}] "
                    f"malicious={malicious_percent:>2}% "
                    f"trial={trial}/{trials}"
                )

                # One shared environment means both conditions use the
                # exact same identities and cryptographic keys.
                with contextlib.redirect_stdout(io.StringIO()):
                    ta, sender, responder = build_environment(scenario)

                    generator = MutualAuthentication(ta)
                    baseline_manager = MutualAuthentication(ta)
                    act_manager = MutualAuthentication(ta)

                    # Warm-up is not measured.
                    warm_up(ta, sender, responder)

                    workload = generate_workload(
                        generator,
                        sender,
                        responder,
                        requests_per_trial,
                        malicious_percent,
                        seed=(
                            20260926
                            + trial * 1000
                            + malicious_percent * 17
                            + (0 if scenario == "v2v" else 500000)
                        ),
                    )

                    # Alternate order between conditions across trials.
                    # This reduces systematic ordering/thermal effects.
                    if trial % 2 == 1:
                        baseline = run_batch(
                            baseline_manager,
                            sender,
                            responder,
                            workload,
                            use_act=False,
                        )
                        proposed = run_batch(
                            act_manager,
                            sender,
                            responder,
                            workload,
                            use_act=True,
                        )
                    else:
                        proposed = run_batch(
                            act_manager,
                            sender,
                            responder,
                            workload,
                            use_act=True,
                        )
                        baseline = run_batch(
                            baseline_manager,
                            sender,
                            responder,
                            workload,
                            use_act=False,
                        )

                raw_rows.append({
                    "scenario": scenario,
                    "trial": trial,
                    "malicious_percent": malicious_percent,
                    "total_requests": requests_per_trial,
                    "malicious_requests": baseline["malicious"],
                    "valid_requests": baseline["valid"],

                    "baseline_average_time_ms":
                        f'{baseline["average_time_ms"]:.6f}',
                    "act_average_time_ms":
                        f'{proposed["average_time_ms"]:.6f}',

                    "baseline_total_time_ms":
                        f'{baseline["total_time_ms"]:.6f}',
                    "act_total_time_ms":
                        f'{proposed["total_time_ms"]:.6f}',

                    "baseline_mldsa_verify":
                        baseline["mldsa_verify"],
                    "act_mldsa_verify":
                        proposed["mldsa_verify"],

                    "baseline_kem_total":
                        baseline["kem_total"],
                    "act_kem_total":
                        proposed["kem_total"],

                    "baseline_kem_keygen":
                        baseline["kem_keygen"],
                    "act_kem_keygen":
                        proposed["kem_keygen"],

                    "baseline_kem_encapsulate":
                        baseline["kem_encapsulate"],
                    "act_kem_encapsulate":
                        proposed["kem_encapsulate"],

                    "baseline_kem_decapsulate":
                        baseline["kem_decapsulate"],
                    "act_kem_decapsulate":
                        proposed["kem_decapsulate"],

                    "baseline_rejected":
                        baseline["rejected"],
                    "act_rejected":
                        proposed["rejected"],

                    "baseline_rejection_latency_ms": (
                        ""
                        if math.isnan(baseline["rejection_latency_ms"])
                        else f'{baseline["rejection_latency_ms"]:.6f}'
                    ),
                    "act_rejection_latency_ms": (
                        ""
                        if math.isnan(proposed["rejection_latency_ms"])
                        else f'{proposed["rejection_latency_ms"]:.6f}'
                    ),

                    "baseline_throughput":
                        f'{baseline["throughput"]:.6f}',
                    "act_throughput":
                        f'{proposed["throughput"]:.6f}',

                    "baseline_process_cpu_percent":
                        f'{baseline["process_cpu_percent"]:.6f}',
                    "act_process_cpu_percent":
                        f'{proposed["process_cpu_percent"]:.6f}',

                    "mldsa_avoided_percent":
                        f'{percent_avoided(baseline["mldsa_verify"], proposed["mldsa_verify"]):.6f}',
                    "kem_avoided_percent":
                        f'{percent_avoided(baseline["kem_total"], proposed["kem_total"]):.6f}',
                })

    raw_fields = list(raw_rows[0].keys())
    write_csv(
        RAW_CSV,
        raw_rows,
        raw_fields,
    )

    summary_rows = summarize(raw_rows)
    summary_fields = list(summary_rows[0].keys())
    write_csv(
        SUMMARY_CSV,
        summary_rows,
        summary_fields,
    )

    print()
    print("=" * 78)
    print("ACT ABLATION COMPLETED")
    print("=" * 78)
    print(f"Raw results     : {RAW_CSV}")
    print(f"Summary results : {SUMMARY_CSV}")
    print("=" * 78)

    return raw_rows, summary_rows


def main():
    parser = argparse.ArgumentParser(
        description="Run ACT ablation for the current PQC-VANET implementation."
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=DEFAULT_TRIALS,
        help=f"Number of repeated trials (default: {DEFAULT_TRIALS})",
    )

    parser.add_argument(
        "--requests",
        type=int,
        default=DEFAULT_REQUESTS,
        help=f"Requests per traffic level and trial (default: {DEFAULT_REQUESTS})",
    )

    parser.add_argument(
        "--scenario",
        choices=("v2v", "v2i", "both"),
        default="v2v",
        help="Run V2V, V2I, or both (default: v2v)",
    )

    args = parser.parse_args()

    if args.trials < 1:
        raise SystemExit("--trials must be >= 1")

    if args.requests < 1:
        raise SystemExit("--requests must be >= 1")

    if args.scenario == "both":
        scenarios = ("v2v", "v2i")
    else:
        scenarios = (args.scenario,)

    run_experiment(
        trials=args.trials,
        requests_per_trial=args.requests,
        scenarios=scenarios,
    )


if __name__ == "__main__":
    main()
