import csv
import os
import matplotlib.pyplot as plt

INPUT_FILE = os.path.join("results", "crypto_timing_summary.csv")
OUTPUT_DIR = "results"

mldsa_ops = []
mldsa_mean = []
mldsa_std = []

mlkem_ops = []
mlkem_mean = []
mlkem_std = []

with open(INPUT_FILE, "r", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:
        primitive = row["primitive"]
        operation = row["operation"]
        mean = float(row["mean_ms"])
        std = float(row["std_ms"])

        if primitive == "ML-DSA-65":
            mldsa_ops.append(operation)
            mldsa_mean.append(mean)
            mldsa_std.append(std)

        elif primitive == "ML-KEM-768":
            mlkem_ops.append(operation)
            mlkem_mean.append(mean)
            mlkem_std.append(std)


def make_plot(primitive, operations, means, stds, filename):
    plt.figure(figsize=(8, 5.5))

    x = range(len(operations))

    plt.errorbar(
        x,
        means,
        yerr=stds,
        fmt="o-",
        linewidth=2,
        markersize=7,
        capsize=5
    )

    plt.xticks(
        list(x),
        operations,
        rotation=15
    )

    plt.xlabel("Cryptographic Operation", fontsize=12)
    plt.ylabel("Execution Time (ms)", fontsize=12)
    plt.title(
        f"{primitive} Cryptographic Operation Timing",
        fontsize=13
    )

    plt.grid(
        True,
        linestyle="--",
        alpha=0.5
    )

    plt.tight_layout()

    png_path = os.path.join(OUTPUT_DIR, filename + ".png")
    pdf_path = os.path.join(OUTPUT_DIR, filename + ".pdf")

    plt.savefig(
        png_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.savefig(
        pdf_path,
        bbox_inches="tight"
    )

    plt.close()

    print(f"Saved: {png_path}")
    print(f"Saved: {pdf_path}")


make_plot(
    "ML-DSA-65",
    mldsa_ops,
    mldsa_mean,
    mldsa_std,
    "crypto_timing_mldsa"
)

make_plot(
    "ML-KEM-768",
    mlkem_ops,
    mlkem_mean,
    mlkem_std,
    "crypto_timing_mlkem"
)

print("\nCrypto timing figures generated successfully.")
