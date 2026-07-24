"""
=========================================================
Research Benchmark Utilities
---------------------------------------------------------
Professional benchmarking framework for the PQC-VANET
protocol.

Features
--------
• Nanosecond precision timing
• Warm-up execution
• Statistical analysis
• Raw & Summary CSV generation
• IEEE publication-ready benchmarking
=========================================================
"""

import csv
import math
import os
import statistics
import time
from typing import Callable, Dict, List

# =========================================================
# Configuration
# =========================================================

GRAPH_DATA_FOLDER = "performance_evaluation/graph_data"

DEFAULT_ITERATIONS = 30

TIME_UNIT = "ms"

os.makedirs(GRAPH_DATA_FOLDER, exist_ok=True)


# =========================================================
# High Precision Timer
# =========================================================

class BenchmarkTimer:
    """
    High precision benchmark timer.

    Uses perf_counter_ns() for nanosecond precision and
    converts the result into milliseconds.
    """

    def __init__(self):

        self.start_time = None

        self.end_time = None

    # -----------------------------------------------------

    def start(self):

        self.start_time = time.perf_counter_ns()

    # -----------------------------------------------------

    def stop(self):

        if self.start_time is None:

            raise RuntimeError(
                "BenchmarkTimer.start() must be called first."
            )

        self.end_time = time.perf_counter_ns()

        elapsed_ns = self.end_time - self.start_time

        elapsed_ms = elapsed_ns / 1_000_000

        return elapsed_ms

    # -----------------------------------------------------

    def reset(self):

        self.start_time = None

        self.end_time = None


# =========================================================
# Benchmark Statistics
# (Implemented in Part 2)
# =========================================================

class BenchmarkStatistics:
    pass


# =========================================================
# CSV Writer
# (Implemented in Part 3)
# =========================================================

class CSVWriter:
    pass


# =========================================================
# Benchmark Runner
# (Implemented in Part 4)
# =========================================================
# =========================================================
# Benchmark Statistics
# =========================================================

class BenchmarkStatistics:
    """
    Computes professional benchmark statistics for a list
    of execution time samples.
    """

    @staticmethod
    def calculate(samples: List[float]) -> Dict:

        if not samples:

            return {

                "samples": [],

                "count": 0,

                "average": 0,

                "median": 0,

                "minimum": 0,

                "maximum": 0,

                "range": 0,

                "variance": 0,

                "std_dev": 0,

                "confidence95": 0

            }

        count = len(samples)

        average = statistics.mean(samples)

        median = statistics.median(samples)

        minimum = min(samples)

        maximum = max(samples)

        sample_range = maximum - minimum

        if count > 1:

            variance = statistics.variance(samples)

            std_dev = statistics.stdev(samples)

            confidence95 = 1.96 * (

                std_dev / math.sqrt(count)

            )

        else:

            variance = 0

            std_dev = 0

            confidence95 = 0

        return {

            "samples": [

                round(value, 6)

                for value in samples

            ],

            "count": count,

            "average": round(

                average,

                6

            ),

            "median": round(

                median,

                6

            ),

            "minimum": round(

                minimum,

                6

            ),

            "maximum": round(

                maximum,

                6

            ),

            "range": round(

                sample_range,

                6

            ),

            "variance": round(

                variance,

                6

            ),

            "std_dev": round(

                std_dev,

                6

            ),

            "confidence95": round(

                confidence95,

                6

            )

        }

    # -----------------------------------------------------

    @staticmethod
    def print_report(results: Dict):

        print("\n")

        print("=" * 55)

        print("BENCHMARK STATISTICS")

        print("=" * 55)

        print(f"Samples           : {results['count']}")

        print(f"Average (ms)      : {results['average']}")

        print(f"Median (ms)       : {results['median']}")

        print(f"Minimum (ms)      : {results['minimum']}")

        print(f"Maximum (ms)      : {results['maximum']}")

        print(f"Range (ms)        : {results['range']}")

        print(f"Std Dev (ms)      : {results['std_dev']}")

        print(f"Variance          : {results['variance']}")

        print(f"95% Confidence    : ±{results['confidence95']}")

        print("=" * 55)
        # =========================================================
# CSV Writer
# =========================================================

class CSVWriter:
    """
    Exports benchmark results into CSV files.

    Two CSV files are generated:

    1. Raw benchmark data
    2. Statistical summary
    """

    def __init__(self):

        self.output_folder = GRAPH_DATA_FOLDER

        os.makedirs(

            self.output_folder,

            exist_ok=True

        )

    # -----------------------------------------------------
    # Raw Samples
    # -----------------------------------------------------

    def save_raw(self,
                 operation: str,
                 samples: List[float]):

        filename = f"{operation.lower()}_raw.csv"

        filepath = os.path.join(

            self.output_folder,

            filename

        )

        with open(

            filepath,

            "w",

            newline=""

        ) as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow([

                "Run",

                "Latency(ms)"

            ])

            for index, sample in enumerate(

                samples,

                start=1

            ):

                writer.writerow([

                    index,

                    round(sample, 6)

                ])

        print(f"[✓] Raw CSV Saved : {filepath}")

    # -----------------------------------------------------
    # Summary Statistics
    # -----------------------------------------------------

    def save_summary(self,
                     operation: str,
                     results: Dict):

        filename = f"{operation.lower()}_summary.csv"

        filepath = os.path.join(

            self.output_folder,

            filename

        )

        with open(

            filepath,

            "w",

            newline=""

        ) as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow([

                "Metric",

                "Value"

            ])

            writer.writerow(["Average", results["average"]])

            writer.writerow(["Median", results["median"]])

            writer.writerow(["Minimum", results["minimum"]])

            writer.writerow(["Maximum", results["maximum"]])

            writer.writerow(["Range", results["range"]])

            writer.writerow(["Variance", results["variance"]])

            writer.writerow(["Std Dev", results["std_dev"]])

            writer.writerow([

                "Confidence95",

                results["confidence95"]

            ])

            writer.writerow(["Samples", results["count"]])

        print(f"[✓] Summary CSV Saved : {filepath}")

    # -----------------------------------------------------
    # Complete Export
    # -----------------------------------------------------

    def export(self,
               operation: str,
               results: Dict):

        self.save_raw(

            operation,

            results["samples"]

        )

        self.save_summary(

            operation,

            results

        )
        # =========================================================
# Benchmark Runner
# =========================================================

class BenchmarkRunner:
    """
    Executes benchmarks using a warm-up run followed by
    repeated timed executions.

    Returns complete benchmark statistics and automatically
    exports both raw and summary CSV files.
    """

    def __init__(self,
                 iterations: int = DEFAULT_ITERATIONS,
                 warmup: bool = True,
                 auto_export: bool = True):

        self.iterations = iterations

        self.warmup = warmup

        self.auto_export = auto_export

        self.timer = BenchmarkTimer()

        self.csv = CSVWriter()

    # -----------------------------------------------------

    def execute(self,
                operation: str,
                function: Callable,
                iterations=None
            ):

        print("\n")
        print("=" * 60)
        print(f"Benchmark : {operation}")
        print("=" * 60)

        # -----------------------------------------------
        # Warm-up
        # -----------------------------------------------

        if self.warmup:

            try:

                function()

                print("[✓] Warm-up Completed")

            except Exception as error:

                print(f"[!] Warm-up Failed : {error}")

        # -----------------------------------------------
        # Benchmark Loop
        # -----------------------------------------------

        if iterations is None:
            iterations = self.iterations

        samples = []

        for run in range(iterations):

            self.timer.reset()

            self.timer.start()

            function()

            elapsed = self.timer.stop()

            samples.append(elapsed)

        # -----------------------------------------------
        # Statistics
        # -----------------------------------------------

        results = BenchmarkStatistics.calculate(

            samples

        )

        # -----------------------------------------------
        # Console Report
        # -----------------------------------------------

        BenchmarkStatistics.print_report(

            results

        )

        # -----------------------------------------------
        # CSV Export
        # -----------------------------------------------

        if self.auto_export:

            self.csv.export(

                operation,

                results

            )

        return results

    # -----------------------------------------------------

    def benchmark_multiple(self,
                           benchmarks: Dict[str, Callable]):

        results = {}

        for name, function in benchmarks.items():

            results[name] = self.execute(

                name,

                function

            )

        return results
        # =========================================================
# Benchmark Utilities
# =========================================================

import tracemalloc


class BenchmarkAnalyzer:
    """
    Additional benchmark analysis utilities.

    Provides:
        • Outlier Detection
        • Memory Measurement
        • Unit Conversion
        • Benchmark Validation
    """

    # -----------------------------------------------------
    # IQR Outlier Detection
    # -----------------------------------------------------

    @staticmethod
    def detect_outliers(samples: List[float]):

        if len(samples) < 4:

            return []

        sorted_samples = sorted(samples)

        q1 = statistics.quantiles(

            sorted_samples,

            n=4

        )[0]

        q3 = statistics.quantiles(

            sorted_samples,

            n=4

        )[2]

        iqr = q3 - q1

        lower = q1 - 1.5 * iqr

        upper = q3 + 1.5 * iqr

        return [

            value

            for value in samples

            if value < lower or value > upper

        ]

    # -----------------------------------------------------
    # Memory Usage
    # -----------------------------------------------------

    @staticmethod
    def measure_memory(function: Callable):

        tracemalloc.start()

        function()

        current, peak = tracemalloc.get_traced_memory()

        tracemalloc.stop()

        return {

            "current_kb": round(

                current / 1024,

                3

            ),

            "peak_kb": round(

                peak / 1024,

                3

            )

        }

    # -----------------------------------------------------
    # Time Formatting
    # -----------------------------------------------------

    @staticmethod
    def format_time(milliseconds: float):

        if milliseconds < 0.001:

            return f"{milliseconds*1000000:.3f} ns"

        elif milliseconds < 1:

            return f"{milliseconds*1000:.3f} µs"

        elif milliseconds < 1000:

            return f"{milliseconds:.3f} ms"

        else:

            return f"{milliseconds/1000:.3f} s"

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------

    @staticmethod
    def validate(results: Dict):

        if results["count"] == 0:

            raise RuntimeError(

                "No benchmark samples collected."

            )

        if results["average"] <= 0:

            raise RuntimeError(

                "Average execution time is invalid."

            )

        return True

    # -----------------------------------------------------
    # Report
    # -----------------------------------------------------

    @staticmethod
    def report(results: Dict):

        outliers = BenchmarkAnalyzer.detect_outliers(

            results["samples"]

        )

        print("\n")
        print("=" * 60)
        print("BENCHMARK ANALYSIS")
        print("=" * 60)

        print(

            f"Samples            : {results['count']}"

        )

        print(

            f"Average            : {BenchmarkAnalyzer.format_time(results['average'])}"

        )

        print(

            f"Median             : {BenchmarkAnalyzer.format_time(results['median'])}"

        )

        print(

            f"Std Dev            : {results['std_dev']:.6f}"

        )

        print(

            f"95% Confidence     : ±{results['confidence95']:.6f}"

        )

        print(

            f"Outliers Detected  : {len(outliers)}"

        )

        print("=" * 60)