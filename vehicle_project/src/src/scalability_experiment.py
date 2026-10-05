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
RAW_FILE = RESULTS_DIR / "scalability_raw.csv"
SUMMARY_FILE = RESULTS_DIR / "scalability_summary.csv"

def quiet_call(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)

def build_environment(vehicle_count, rsu_count):
    ta = TrustedAuthority()
    rsus = []
    for i in range(1, rsu_count + 1):
        rsu = RSU(rsu_id=f"RSU{i:03d}", trusted_authority=ta)
        ta.register_rsu(rsu)
        quiet_call(rsu.register)
        quiet_call(rsu.initialize_crypto)
        rsus.append(rsu)

    vehicles = []
    for i in range(1, vehicle_count + 1):
        vehicles.append(Vehicle(
            real_id=f"VEHICLE{i:03d}",
            trusted_authority=ta
        ))

    for vehicle in vehicles:
        if not quiet_call(ta.register_vehicle, vehicle):
            raise RuntimeError(f"Vehicle registration failed: {vehicle.real_id}")

    keygen = CertificatelessKeyGeneration(ta)
    quiet_call(keygen.generate_keys_for_all, vehicles)
    quiet_call(keygen.verify_all, vehicles)

    pseudonyms = PseudonymGeneration(ta)
    quiet_call(pseudonyms.generate_for_all, vehicles)
    quiet_call(pseudonyms.verify_all, vehicles)

    return ta, rsus, vehicles

def run_trial(ta, vehicles, requests):
    if len(vehicles) < 2:
        raise ValueError("At least two vehicles are required.")

    manager = MutualAuthentication(ta)
    sender, responder = vehicles[0], vehicles[1]

    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    times = []
    successful = 0
    failed = 0

    for _ in range(requests):
        start = time.perf_counter()
        try:
            result = quiet_call(manager.authenticate, sender, responder)
        except Exception:
            result = False
        elapsed = (time.perf_counter() - start) * 1000
        if result:
            successful += 1
            times.append(elapsed)
        else:
            failed += 1

    wall = time.perf_counter() - wall_start
    cpu = time.process_time() - cpu_start

    return {
        "average_latency_ms": statistics.mean(times) if times else 0.0,
        "throughput_requests_per_sec": successful / wall if wall > 0 else 0.0,
        "process_cpu_percent": (cpu / wall) * 100 if wall > 0 else 0.0,
        "successful_authentications": successful,
        "failed_authentications": failed,
    }

def warmup(vehicle_count, rsu_count):
    ta, rsus, vehicles = build_environment(vehicle_count, rsu_count)
    run_trial(ta, vehicles, 3)
    del ta, rsus, vehicles
    gc.collect()

def mean_std(values):
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, std

def main():
    parser = argparse.ArgumentParser(description="PQC-VANET scalability experiment")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--rsus", type=int, default=2)
    parser.add_argument("--vehicles", type=int, nargs="+",
                        default=[5, 10, 20, 50, 100])
    args = parser.parse_args()

    if args.trials < 1 or args.requests < 1 or args.rsus < 1:
        raise ValueError("trials, requests and rsus must be positive.")
    if any(v < 2 for v in args.vehicles):
        raise ValueError("Each vehicle count must be at least 2.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 78)
    print("PQC-VANET SCALABILITY EXPERIMENT")
    print("=" * 78)
    print(f"Vehicle counts     : {args.vehicles}")
    print(f"RSUs               : {args.rsus}")
    print(f"Trials per size    : {args.trials}")
    print(f"Requests per trial : {args.requests}")
    print("=" * 78)

    print("\nWarm-up run...")
    warmup(min(args.vehicles), args.rsus)

    raw = []

    for n in args.vehicles:
        for trial in range(1, args.trials + 1):
            print(f"[scalability] vehicles={n:3d} trial={trial}/{args.trials}")
            ta, rsus, vehicles = build_environment(n, args.rsus)
            result = run_trial(ta, vehicles, args.requests)
            result.update({
                "scenario": "v2v",
                "vehicles": n,
                "rsus": args.rsus,
                "trial": trial,
                "requests_per_trial": args.requests,
            })
            raw.append(result)
            del ta, rsus, vehicles
            gc.collect()

    raw_fields = [
        "scenario","vehicles","rsus","trial","requests_per_trial",
        "average_latency_ms","throughput_requests_per_sec",
        "process_cpu_percent","successful_authentications",
        "failed_authentications"
    ]
    with RAW_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=raw_fields)
        writer.writeheader()
        writer.writerows(raw)

    summary = []
    for n in args.vehicles:
        group = [r for r in raw if r["vehicles"] == n]
        lm, ls = mean_std([r["average_latency_ms"] for r in group])
        tm, ts = mean_std([r["throughput_requests_per_sec"] for r in group])
        cm, cs = mean_std([r["process_cpu_percent"] for r in group])
        sm, ss = mean_std([r["successful_authentications"] for r in group])
        fm, fs = mean_std([r["failed_authentications"] for r in group])
        summary.append({
            "scenario":"v2v","vehicles":n,"rsus":args.rsus,
            "trials":len(group),"requests_per_trial":args.requests,
            "average_latency_ms_mean":lm,"average_latency_ms_std":ls,
            "throughput_requests_per_sec_mean":tm,
            "throughput_requests_per_sec_std":ts,
            "process_cpu_percent_mean":cm,"process_cpu_percent_std":cs,
            "successful_authentications_mean":sm,
            "successful_authentications_std":ss,
            "failed_authentications_mean":fm,
            "failed_authentications_std":fs
        })

    summary_fields = [
        "scenario","vehicles","rsus","trials","requests_per_trial",
        "average_latency_ms_mean","average_latency_ms_std",
        "throughput_requests_per_sec_mean","throughput_requests_per_sec_std",
        "process_cpu_percent_mean","process_cpu_percent_std",
        "successful_authentications_mean","successful_authentications_std",
        "failed_authentications_mean","failed_authentications_std"
    ]
    with SUMMARY_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_fields)
        writer.writeheader()
        writer.writerows(summary)

    print("\n" + "=" * 78)
    print("SCALABILITY EXPERIMENT COMPLETED")
    print("=" * 78)
    for r in summary:
        print(
            f"Vehicles={r['vehicles']:3d} | "
            f"Latency={r['average_latency_ms_mean']:.4f} +/- "
            f"{r['average_latency_ms_std']:.4f} ms | "
            f"Throughput={r['throughput_requests_per_sec_mean']:.2f} +/- "
            f"{r['throughput_requests_per_sec_std']:.2f} req/s | "
            f"CPU proxy={r['process_cpu_percent_mean']:.2f}%"
        )
    print(f"\nRaw results     : {RAW_FILE}")
    print(f"Summary results : {SUMMARY_FILE}")
    print("=" * 78)

if __name__ == "__main__":
    main()
