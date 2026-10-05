import argparse
import csv
import gc
import io
import statistics
import time
import contextlib
from pathlib import Path

from models.trusted_authority import TrustedAuthority
from models.rsu import RSU
from models.vehicle import Vehicle
from certificateless_key_generation import CertificatelessKeyGeneration
from pseudonym_genration import PseudonymGeneration
from mutual_authentication import MutualAuthentication

RESULTS_DIR = Path("results")
RAW_FILE = RESULTS_DIR / "scalability_network_raw.csv"
SUMMARY_FILE = RESULTS_DIR / "scalability_network_summary.csv"


def quiet_call(fn, *args, **kwargs):
    """Run a project function without flooding the console."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def build_environment(vehicle_count, rsu_count):
    """
    Build a fresh PQC-VANET network for one trial.

    Setup/key-generation time is NOT included in the authentication
    measurements.
    """
    ta = TrustedAuthority()

    rsus = []
    for i in range(1, rsu_count + 1):
        rsu = RSU(
            rsu_id=f"RSU{i:03d}",
            trusted_authority=ta
        )
        ta.register_rsu(rsu)
        quiet_call(rsu.register)
        quiet_call(rsu.initialize_crypto)
        rsus.append(rsu)

    vehicles = []
    for i in range(1, vehicle_count + 1):
        vehicles.append(
            Vehicle(
                real_id=f"VEHICLE{i:03d}",
                trusted_authority=ta
            )
        )

    for vehicle in vehicles:
        if not quiet_call(ta.register_vehicle, vehicle):
            raise RuntimeError(
                f"Vehicle registration failed: {vehicle.real_id}"
            )

    keygen = CertificatelessKeyGeneration(ta)
    quiet_call(keygen.generate_keys_for_all, vehicles)
    quiet_call(keygen.verify_all, vehicles)

    pseudonyms = PseudonymGeneration(ta)
    quiet_call(pseudonyms.generate_for_all, vehicles)
    quiet_call(pseudonyms.verify_all, vehicles)

    return ta, rsus, vehicles


def build_authentication_workload(vehicles, rsus):
    """
    Create a deterministic network-wide authentication workload.

    V2V:
        VEHICLE001 -> VEHICLE002
        VEHICLE002 -> VEHICLE003
        ...
        VEHICLE(N-1) -> VEHICLE(N)

    V2I:
        Every vehicle authenticates with an RSU using round-robin
        assignment across the configured RSUs.

    Therefore, for N vehicles:
        V2V authentications = N - 1
        V2I authentications = N
        Total authentications = 2N - 1
    """
    workload = []

    # V2V: neighbouring vehicle pairs
    for i in range(len(vehicles) - 1):
        workload.append(
            ("V2V", vehicles[i], vehicles[i + 1])
        )

    # V2I: every vehicle authenticates to an RSU
    if rsus:
        for i, vehicle in enumerate(vehicles):
            rsu = rsus[i % len(rsus)]
            workload.append(
                ("V2I", vehicle, rsu)
            )

    return workload


def run_trial(ta, vehicles, rsus):
    """
    Measure authentication of the whole configured network.

    The timer covers only the M1-M4 authentication execution.
    Registration, key generation and pseudonym setup are excluded.
    """
    workload = build_authentication_workload(vehicles, rsus)

    if not workload:
        raise ValueError("Authentication workload is empty.")

    manager = MutualAuthentication(ta)

    successful = 0
    failed = 0
    latencies = []

    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    for _kind, sender, receiver in workload:
        start = time.perf_counter()

        try:
            result = quiet_call(
                manager.authenticate,
                sender,
                receiver
            )
        except Exception:
            result = False

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if result:
            successful += 1
            latencies.append(elapsed_ms)
        else:
            failed += 1

    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start

    total_authentications = len(workload)

    return {
        "total_authentications": total_authentications,
        "successful_authentications": successful,
        "failed_authentications": failed,
        "average_latency_ms": (
            statistics.mean(latencies) if latencies else 0.0
        ),
        "median_latency_ms": (
            statistics.median(latencies) if latencies else 0.0
        ),
        "total_authentication_time_ms": (
            sum(latencies) if latencies else 0.0
        ),
        "throughput_requests_per_sec": (
            successful / wall_seconds
            if wall_seconds > 0 else 0.0
        ),
        "process_cpu_percent": (
            (cpu_seconds / wall_seconds) * 100.0
            if wall_seconds > 0 else 0.0
        ),
    }


def warmup(vehicle_count, rsu_count):
    """Unmeasured warm-up."""
    ta, rsus, vehicles = build_environment(
        vehicle_count,
        rsu_count
    )
    run_trial(ta, vehicles, rsus)

    del ta, rsus, vehicles
    gc.collect()


def mean_std(values):
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, std


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PQC-VANET network-wide scalability experiment "
            "using the actual M1-M4 authentication path."
        )
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=10
    )

    parser.add_argument(
        "--rsus",
        type=int,
        default=2
    )

    parser.add_argument(
        "--vehicles",
        type=int,
        nargs="+",
        default=[5, 10, 20, 50, 100]
    )

    args = parser.parse_args()

    if args.trials < 1:
        raise ValueError("trials must be positive.")

    if args.rsus < 1:
        raise ValueError("rsus must be positive.")

    if any(v < 2 for v in args.vehicles):
        raise ValueError(
            "Every vehicle count must be at least 2."
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 78)
    print("PQC-VANET NETWORK-WIDE SCALABILITY EXPERIMENT")
    print("=" * 78)
    print(f"Vehicle counts : {args.vehicles}")
    print(f"RSUs           : {args.rsus}")
    print(f"Trials/size    : {args.trials}")
    print()
    print("For N vehicles:")
    print("  V2V authentications = N - 1")
    print("  V2I authentications = N")
    print("  Total authentications = 2N - 1")
    print("=" * 78)

    print("\nWarm-up run...")
    warmup(min(args.vehicles), args.rsus)

    raw = []

    for vehicle_count in args.vehicles:
        for trial in range(1, args.trials + 1):

            print(
                f"[scalability] "
                f"vehicles={vehicle_count:3d} "
                f"trial={trial}/{args.trials}"
            )

            ta, rsus, vehicles = build_environment(
                vehicle_count,
                args.rsus
            )

            result = run_trial(
                ta,
                vehicles,
                rsus
            )

            result.update({
                "scenario": "network-wide",
                "vehicles": vehicle_count,
                "rsus": args.rsus,
                "trial": trial,
            })

            raw.append(result)

            del ta, rsus, vehicles
            gc.collect()

    raw_fields = [
        "scenario",
        "vehicles",
        "rsus",
        "trial",
        "total_authentications",
        "successful_authentications",
        "failed_authentications",
        "average_latency_ms",
        "median_latency_ms",
        "total_authentication_time_ms",
        "throughput_requests_per_sec",
        "process_cpu_percent",
    ]

    with RAW_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=raw_fields
        )
        writer.writeheader()
        writer.writerows(raw)

    summary = []

    for vehicle_count in args.vehicles:
        group = [
            row for row in raw
            if row["vehicles"] == vehicle_count
        ]

        lm, ls = mean_std([
            row["average_latency_ms"]
            for row in group
        ])

        mdm, mds = mean_std([
            row["median_latency_ms"]
            for row in group
        ])

        tm, ts = mean_std([
            row["total_authentication_time_ms"]
            for row in group
        ])

        thm, ths = mean_std([
            row["throughput_requests_per_sec"]
            for row in group
        ])

        cm, cs = mean_std([
            row["process_cpu_percent"]
            for row in group
        ])

        sm, ss = mean_std([
            row["successful_authentications"]
            for row in group
        ])

        fm, fs = mean_std([
            row["failed_authentications"]
            for row in group
        ])

        summary.append({
            "scenario": "network-wide",
            "vehicles": vehicle_count,
            "rsus": args.rsus,
            "trials": len(group),
            "expected_authentications_per_trial": (
                2 * vehicle_count - 1
            ),
            "requests_per_trial": (
                2 * vehicle_count - 1
            ),
            "average_latency_ms_mean": lm,
            "average_latency_ms_std": ls,
            "median_latency_ms_mean": mdm,
            "median_latency_ms_std": mds,
            "total_authentication_time_ms_mean": tm,
            "total_authentication_time_ms_std": ts,
            "throughput_requests_per_sec_mean": thm,
            "throughput_requests_per_sec_std": ths,
            "process_cpu_percent_mean": cm,
            "process_cpu_percent_std": cs,
            "successful_authentications_mean": sm,
            "successful_authentications_std": ss,
            "failed_authentications_mean": fm,
            "failed_authentications_std": fs,
        })

    summary_fields = [
        "scenario",
        "vehicles",
        "rsus",
        "trials",
        "expected_authentications_per_trial",
        "requests_per_trial",
        "average_latency_ms_mean",
        "average_latency_ms_std",
        "median_latency_ms_mean",
        "median_latency_ms_std",
        "total_authentication_time_ms_mean",
        "total_authentication_time_ms_std",
        "throughput_requests_per_sec_mean",
        "throughput_requests_per_sec_std",
        "process_cpu_percent_mean",
        "process_cpu_percent_std",
        "successful_authentications_mean",
        "successful_authentications_std",
        "failed_authentications_mean",
        "failed_authentications_std",
    ]

    with SUMMARY_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=summary_fields
        )
        writer.writeheader()
        writer.writerows(summary)

    print("\n" + "=" * 78)
    print("NETWORK-WIDE SCALABILITY EXPERIMENT COMPLETED")
    print("=" * 78)

    for row in summary:
        print(
            f"Vehicles={row['vehicles']:3d} | "
            f"Auth/trial={row['expected_authentications_per_trial']:3d} | "
            f"Latency="
            f"{row['average_latency_ms_mean']:.4f} +/- "
            f"{row['average_latency_ms_std']:.4f} ms | "
            f"Throughput="
            f"{row['throughput_requests_per_sec_mean']:.2f} +/- "
            f"{row['throughput_requests_per_sec_std']:.2f} req/s | "
            f"CPU proxy="
            f"{row['process_cpu_percent_mean']:.2f}%"
        )

    print(f"\nRaw results     : {RAW_FILE}")
    print(f"Summary results : {SUMMARY_FILE}")
    print("=" * 78)


if __name__ == "__main__":
    main()

