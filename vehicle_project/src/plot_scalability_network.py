import csv
import os
import matplotlib.pyplot as plt


# ============================================================
# Configuration
# ============================================================

INPUT_FILE = os.path.join(
    "results",
    "scalability_network_summary.csv"
)

OUTPUT_DIR = "results"


# ============================================================
# Read CSV
# ============================================================

vehicles = []

latency_mean = []
latency_std = []

throughput_mean = []
throughput_std = []

cpu_mean = []
cpu_std = []


with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        vehicles.append(int(row["vehicles"]))

        latency_mean.append(
            float(row["average_latency_ms_mean"])
        )

        latency_std.append(
            float(row["average_latency_ms_std"])
        )

        throughput_mean.append(
            float(row["throughput_requests_per_sec_mean"])
        )

        throughput_std.append(
            float(row["throughput_requests_per_sec_std"])
        )

        cpu_mean.append(
            float(row["process_cpu_percent_mean"])
        )

        cpu_std.append(
            float(row["process_cpu_percent_std"])
        )


# ============================================================
# Plot function
# ============================================================

def save_plot(
    filename,
    x,
    y,
    yerr,
    xlabel,
    ylabel,
    title
):

    plt.figure(figsize=(8, 5.5))

    plt.errorbar(
        x,
        y,
        yerr=yerr,
        marker="o",
        markersize=6,
        linewidth=2,
        capsize=5
    )

    plt.xlabel(
        xlabel,
        fontsize=12
    )

    plt.ylabel(
        ylabel,
        fontsize=12
    )

    plt.title(
        title,
        fontsize=13
    )

    plt.grid(
        True,
        linestyle="--",
        alpha=0.5
    )

    plt.xticks(x)

    plt.tight_layout()

    png_path = os.path.join(
        OUTPUT_DIR,
        filename + ".png"
    )

    pdf_path = os.path.join(
        OUTPUT_DIR,
        filename + ".pdf"
    )

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


# ============================================================
# Figure 1 — Authentication Latency
# ============================================================

save_plot(
    filename="scalability_latency",

    x=vehicles,

    y=latency_mean,

    yerr=latency_std,

    xlabel="Number of Vehicles",

    ylabel="Authentication Latency (ms)",

    title="Authentication Latency vs Vehicle Population"
)


# ============================================================
# Figure 2 — Throughput
# ============================================================

save_plot(
    filename="scalability_throughput",

    x=vehicles,

    y=throughput_mean,

    yerr=throughput_std,

    xlabel="Number of Vehicles",

    ylabel="Throughput (authentications/s)",

    title="Authentication Throughput vs Vehicle Population"
)


# ============================================================
# Figure 3 — Process CPU Proxy
# ============================================================

save_plot(
    filename="scalability_cpu",

    x=vehicles,

    y=cpu_mean,

    yerr=cpu_std,

    xlabel="Number of Vehicles",

    ylabel="Process CPU Proxy (%)",

    title="Process CPU Proxy vs Vehicle Population"
)


print()
print("==============================================")
print("All scalability figures generated successfully")
print("==============================================")