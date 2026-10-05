"""
Plot ACT ablation results.

Input:
    results/act_ablation_summary.csv

Output:
    results/act_ablation_time.png
    results/act_ablation_mldsa.png
    results/act_ablation_kem.png
    results/act_ablation_rejection_latency.png
"""

import csv
from pathlib import Path

import matplotlib.pyplot as plt


SUMMARY_CSV = Path("results/act_ablation_summary.csv")
RESULTS_DIR = Path("results")


def read_csv():
    with SUMMARY_CSV.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def plot_scenario(rows, scenario):
    rows = [
        row for row in rows
        if row["scenario"] == scenario
    ]

    rows.sort(
        key=lambda row: int(row["malicious_percent"])
    )

    x = [
        int(row["malicious_percent"])
        for row in rows
    ]

    baseline_time = [
        float(row["baseline_average_time_ms_mean"])
        for row in rows
    ]

    act_time = [
        float(row["act_average_time_ms_mean"])
        for row in rows
    ]

    baseline_mldsa = [
        float(row["baseline_mldsa_verify_mean"])
        for row in rows
    ]

    act_mldsa = [
        float(row["act_mldsa_verify_mean"])
        for row in rows
    ]

    baseline_kem = [
        float(row["baseline_kem_total_mean"])
        for row in rows
    ]

    act_kem = [
        float(row["act_kem_total_mean"])
        for row in rows
    ]

    act_rejection = [
        float(row["act_rejection_latency_ms_mean"])
        if row["act_rejection_latency_ms_mean"] != ""
        else float("nan")
        for row in rows
    ]

    plt.figure()
    plt.plot(x, baseline_time, marker="o", label="Baseline without ACT")
    plt.plot(x, act_time, marker="o", label="Proposed with ACT")
    plt.xlabel("Malicious Traffic (%)")
    plt.ylabel("Average Authentication Processing Time (ms)")
    plt.title(f"ACT Ablation - Authentication Time ({scenario.upper()})")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIR / f"act_ablation_time_{scenario}.png",
        dpi=300,
    )
    plt.close()

    plt.figure()
    plt.plot(x, baseline_mldsa, marker="o", label="Baseline without ACT")
    plt.plot(x, act_mldsa, marker="o", label="Proposed with ACT")
    plt.xlabel("Malicious Traffic (%)")
    plt.ylabel("ML-DSA Verification Calls")
    plt.title(f"ACT Ablation - ML-DSA Verification ({scenario.upper()})")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIR / f"act_ablation_mldsa_{scenario}.png",
        dpi=300,
    )
    plt.close()

    plt.figure()
    plt.plot(x, baseline_kem, marker="o", label="Baseline without ACT")
    plt.plot(x, act_kem, marker="o", label="Proposed with ACT")
    plt.xlabel("Malicious Traffic (%)")
    plt.ylabel("ML-KEM Operations")
    plt.title(f"ACT Ablation - ML-KEM Operations ({scenario.upper()})")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIR / f"act_ablation_kem_{scenario}.png",
        dpi=300,
    )
    plt.close()

    plt.figure()
    plt.plot(x, act_rejection, marker="o", label="Proposed ACT rejection")
    plt.xlabel("Malicious Traffic (%)")
    plt.ylabel("Rejection Latency (ms)")
    plt.title(f"ACT Ablation - Early Rejection Latency ({scenario.upper()})")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIR / f"act_ablation_rejection_latency_{scenario}.png",
        dpi=300,
    )
    plt.close()


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    rows = read_csv()
    scenarios = sorted({row["scenario"] for row in rows})

    for scenario in scenarios:
        plot_scenario(rows, scenario)

    print("ACT ablation graphs generated in:", RESULTS_DIR)


if __name__ == "__main__":
    main()
