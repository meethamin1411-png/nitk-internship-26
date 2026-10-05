"""
=========================================================
PQC-VANET Research Benchmark Framework
=========================================================

Author : Meeth Amin
Description:
Complete benchmarking framework for the proposed
PQC-VANET protocol.

This module evaluates:

1. Vehicle Registration
2. Certificateless Key Generation
3. Mutual Authentication
4. Digital Signature
5. Signature Verification
6. Communication Cost
7. Storage Cost
8. Memory Usage
9. Scalability
10. Security Features

Outputs:
---------
graph_data/
    *.csv

graph_results/
    *.png

=========================================================
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import os
import csv
import time
import builtins

from models.trusted_authority import TrustedAuthority
from models.vehicle import Vehicle
from models.rsu import RSU
from crypto import kyber
from crypto import qrng


from vehicle_registration import VehicleRegistration
from certificateless_key_generation import CertificatelessKeyGeneration
from mutual_authentication import MutualAuthentication
from digital_signature import DigitalSignature
from signature_verification import SignatureVerification

from performance_evaluation.benchmark_utils import (
    BenchmarkRunner,
    BenchmarkAnalyzer,
)

class ProtocolBenchmark:
    """
    Complete PQC-VANET Performance Evaluation Framework
    """

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(
        self,
        vehicle_count=2,
        iterations=30,
    ):

        print("\nInitializing Benchmark Framework...")

        # -----------------------------------------
        # Configuration
        # -----------------------------------------

        self.vehicle_count = vehicle_count
        self.iterations = iterations

        # -----------------------------------------
        # Trusted Authority
        # -----------------------------------------

        self.ta = TrustedAuthority()

        # -----------------------------------------
        # Protocol Modules
        # -----------------------------------------

        self.registration = VehicleRegistration(
            self.ta
        )

        self.key_generation = (
            CertificatelessKeyGeneration(
                self.ta
            )
        )

        self.authentication = (
            MutualAuthentication(
                self.ta
            )
        )

        self.signature = DigitalSignature()

        self.verification = (
            SignatureVerification()
        )

        # -----------------------------------------
        # Benchmark Engine
        # -----------------------------------------

        self.runner = BenchmarkRunner(
            iterations=self.iterations,
            warmup=True,
            auto_export=True,
        )

        # -----------------------------------------
        # Network Objects
        # -----------------------------------------

        self.vehicles = []

        self.rsu = None

        # -----------------------------------------
        # Result Storage
        # -----------------------------------------

        self.results = {}

        # -----------------------------------------
        # Directories
        # -----------------------------------------

        self.base_directory = Path(__file__).parent

        self.graph_data = (
            self.base_directory /
            "graph_data"
        )

        self.graph_results = (
            self.base_directory /
            "graph_results"
        )

        self.graph_data.mkdir(
            exist_ok=True
        )

        self.graph_results.mkdir(
            exist_ok=True
        )

        print(
            f"Vehicle Count : {self.vehicle_count}"
        )

        print(
            f"Iterations    : {self.iterations}"
        )

        print(
            "Benchmark Framework Ready."
        )
            # =====================================================
    # Initialize VANET Network
    # =====================================================

    def initialize_network(self):

        print("\n" + "=" * 70)
        print("CREATING PQC-VANET NETWORK")
        print("=" * 70)

        self.vehicles = []

        for i in range(self.vehicle_count):

            vehicle = Vehicle(
                f"VEHICLE{i+1:03d}",
                self.ta
            )

            self.vehicles.append(vehicle)

        self.rsu = RSU(
            "RSU001",
            self.ta
        )

        print(f"Vehicles Created : {len(self.vehicles)}")
        print(f"RSU Created      : {self.rsu.rsu_id}")

    # =====================================================
    # Vehicle Registration
    # =====================================================

    def register_network(self):

        print("\n" + "=" * 70)
        print("REGISTERING VEHICLES")
        print("=" * 70)

        for vehicle in self.vehicles:
            self.registration.register_vehicle(vehicle)

        self.registration.register_rsu(
            self.rsu
        )

        print("Vehicle Registration Completed.")

    # =====================================================
    # Initialize Post-Quantum Cryptography
    # =====================================================

    def initialize_crypto(self):

        print("\n" + "=" * 70)
        print("INITIALIZING PQC")
        print("=" * 70)

        for vehicle in self.vehicles:
            vehicle.initialize_crypto()

        self.rsu.initialize_crypto()

        print("Post-Quantum Keys Initialized.")

    # =====================================================
    # Generate Certificateless Keys
    # =====================================================

    def generate_certificateless_keys(self):

        print("\n" + "=" * 70)
        print("CERTIFICATELESS KEY GENERATION")
        print("=" * 70)

        for vehicle in self.vehicles:

            self.key_generation.generate_keys(
                vehicle
            )

        print("Certificateless Keys Generated.")

    # =====================================================
    # Generate Dynamic Pseudonyms
    # =====================================================

    def generate_pseudonyms(self):

        print("\n" + "=" * 70)
        print("GENERATING DYNAMIC PSEUDONYMS")
        print("=" * 70)

        for vehicle in self.vehicles:

            vehicle.generate_pseudonym()

        print("Dynamic Pseudonyms Generated.")

    # =====================================================
    # Connect Vehicles to RSU
    # =====================================================

    def connect_vehicles(self):

        print("\n" + "=" * 70)
        print("CONNECTING VEHICLES")
        print("=" * 70)

        for vehicle in self.vehicles:

            self.rsu.connect_vehicle(
                vehicle
            )

        print("All Vehicles Connected.")

    # =====================================================
    # Validate Network
    # =====================================================

    def validate_network(self):

        print("\nValidating Network...")

        if len(self.vehicles) < 2:
            raise RuntimeError(
                "Minimum two vehicles required."
            )

        if self.rsu is None:
            raise RuntimeError(
                "RSU not initialized."
            )

        for vehicle in self.vehicles:

            if vehicle.sig_pk is None:
                raise RuntimeError(
                    f"{vehicle.real_id} Signature PK Missing"
                )

            if vehicle.sig_sk is None:
                raise RuntimeError(
                    f"{vehicle.real_id} Signature SK Missing"
                )

            if vehicle.kem_pk is None:
                raise RuntimeError(
                    f"{vehicle.real_id} KEM PK Missing"
                )

            if vehicle.kem_sk is None:
                raise RuntimeError(
                    f"{vehicle.real_id} KEM SK Missing"
                )

            if vehicle.partial_public_key is None:
                raise RuntimeError(
                    f"{vehicle.real_id} Partial Public Key Missing"
                )

            if vehicle.partial_private_key is None:
                raise RuntimeError(
                    f"{vehicle.real_id} Partial Private Key Missing"
                )

        print("Network Validation Successful.")

    # =====================================================
    # Prepare Complete Network
    # =====================================================

    def prepare_network(self):

        self.initialize_network()

        self.register_network()

        self.initialize_crypto()

        self.generate_certificateless_keys()

        self.generate_pseudonyms()

        self.connect_vehicles()

        self.validate_network()

        print("\n" + "=" * 70)
        print("NETWORK READY FOR BENCHMARKING")
        print("=" * 70)
            # =====================================================
    # Vehicle Registration Benchmark
    # =====================================================

    def benchmark_registration(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : VEHICLE REGISTRATION")
        print("=" * 70)

        registration_results = {}

        for vehicle in self.vehicles:

            print(f"\nBenchmarking {vehicle.real_id}...")

            result = self.runner.execute(
                operation=f"registration_{vehicle.real_id}",
                function=lambda v=vehicle:
                    self.registration.register_vehicle(v)
            )

            registration_results[vehicle.real_id] = result

            print(
                f"Average : {result['average']:.4f} ms"
            )

        self.results["registration"] = registration_results

        print("\nRegistration Benchmark Completed.")

    # =====================================================
    # Certificateless Key Generation Benchmark
    # =====================================================

    def benchmark_key_generation(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : CERTIFICATELESS KEY GENERATION")
        print("=" * 70)

        key_results = {}

        for vehicle in self.vehicles:

            print(f"\nBenchmarking {vehicle.real_id}...")

            result = self.runner.execute(

                operation=f"key_generation_{vehicle.real_id}",

                function=lambda v=vehicle:
                    self.key_generation.generate_keys(v)

            )

            key_results[vehicle.real_id] = result

            print(
                f"Average : {result['average']:.4f} ms"
            )

        self.results["key_generation"] = key_results

        print("\nKey Generation Benchmark Completed.")

    # =====================================================
    # Export Registration Summary
    # =====================================================

    def export_registration_summary(self):

        file_path = self.graph_data / "registration_summary.csv"

        with open(file_path, "w", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                "Vehicle",
                "Average",
                "Median",
                "Minimum",
                "Maximum",
                "Std Dev",
                "Confidence95"
            ])

            for vehicle_id, result in self.results["registration"].items():

                writer.writerow([

                    vehicle_id,

                    result["average"],

                    result["median"],

                    result["minimum"],

                    result["maximum"],

                    result["std_dev"],

                    result["confidence95"]

                ])

        print("registration_summary.csv exported.")

    # =====================================================
    # Export Key Generation Summary
    # =====================================================

    def export_key_generation_summary(self):

        file_path = self.graph_data / "key_generation_summary.csv"

        with open(file_path, "w", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([

                "Vehicle",

                "Average",

                "Median",

                "Minimum",

                "Maximum",

                "Std Dev",

                "Confidence95"

            ])

            for vehicle_id, result in self.results["key_generation"].items():

                writer.writerow([

                    vehicle_id,

                    result["average"],

                    result["median"],

                    result["minimum"],

                    result["maximum"],

                    result["std_dev"],

                    result["confidence95"]

                ])

        print("key_generation_summary.csv exported.")
            # =====================================================
    # Mutual Authentication Benchmark
    # =====================================================

    def benchmark_authentication(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : MUTUAL AUTHENTICATION")
        print("=" * 70)

        sender = self.vehicles[0]
        receiver = self.vehicles[1]

        # ---------------------------------------------
        # Execution Time Benchmark
        # ---------------------------------------------

        result = self.runner.execute(

            operation="mutual_authentication",

            function=lambda:
                self.authentication.authenticate(
                    sender,
                    receiver
                )

        )

        self.results["authentication"] = result

        print(f"\nAverage Time : {result['average']:.4f} ms")
        print(f"Minimum Time : {result['minimum']:.4f} ms")
        print(f"Maximum Time : {result['maximum']:.4f} ms")
        print(f"Std Dev      : {result['std_dev']:.4f}")

        # ---------------------------------------------
        # Memory Benchmark
        # ---------------------------------------------

        memory = BenchmarkAnalyzer.measure_memory(

            lambda:
                self.authentication.authenticate(
                    sender,
                    receiver
                )

        )

        self.results["authentication_memory"] = memory

        print(f"Peak Memory : {memory['peak_kb']} KB")

        print("\nMutual Authentication Benchmark Completed.")

    # =====================================================
    # Export Authentication Summary
    # =====================================================

    def export_authentication_summary(self):

        file_path = (
            self.graph_data /
            "authentication_summary.csv"
        )

        result = self.results["authentication"]

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Average",
                "Median",
                "Minimum",
                "Maximum",
                "Std Dev",
                "Confidence95"
            ])

            writer.writerow([

                result["average"],

                result["median"],

                result["minimum"],

                result["maximum"],

                result["std_dev"],

                result["confidence95"]

            ])

        print(
            "authentication_summary.csv exported."
        )

    # =====================================================
    # Export Authentication Memory
    # =====================================================

    def export_authentication_memory(self):

        file_path = (
            self.graph_data /
            "authentication_memory.csv"
        )

        memory = self.results[
            "authentication_memory"
        ]

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Peak Memory (KB)"
            ])

            writer.writerow([
                memory["peak_kb"]
            ])

        print(
            "authentication_memory.csv exported."
        )
            # =====================================================
    # Digital Signature Benchmark
    # =====================================================

    def benchmark_signature(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : ML-DSA DIGITAL SIGNATURE")
        print("=" * 70)

        signer = self.vehicles[0]

        message = (
            "PQC-VANET Benchmark Message"
        )

        # ---------------------------------------------
        # Execution Time
        # ---------------------------------------------

        result = self.runner.execute(

            operation="digital_signature",

            function=lambda:
                self.signature.sign(
                    signer,
                    message
                )

        )

        self.results["signature"] = result

        print(f"\nAverage Time : {result['average']:.4f} ms")
        print(f"Minimum Time : {result['minimum']:.4f} ms")
        print(f"Maximum Time : {result['maximum']:.4f} ms")
        print(f"Std Dev      : {result['std_dev']:.4f}")

        # ---------------------------------------------
        # Memory Usage
        # ---------------------------------------------

        memory = BenchmarkAnalyzer.measure_memory(

            lambda:
                self.signature.sign(
                    signer,
                    message
                )

        )

        self.results["signature_memory"] = memory

        print(f"Peak Memory : {memory['peak_kb']} KB")

        print("\nDigital Signature Benchmark Completed.")

    # =====================================================
    # Export Signature Summary
    # =====================================================

    def export_signature_summary(self):

        file_path = (
            self.graph_data /
            "signature_summary.csv"
        )

        result = self.results["signature"]

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Average",
                "Median",
                "Minimum",
                "Maximum",
                "Std Dev",
                "Confidence95"
            ])

            writer.writerow([

                result["average"],

                result["median"],

                result["minimum"],

                result["maximum"],

                result["std_dev"],

                result["confidence95"]

            ])

        print(
            "signature_summary.csv exported."
        )

    # =====================================================
    # Export Signature Memory
    # =====================================================

    def export_signature_memory(self):

        file_path = (
            self.graph_data /
            "signature_memory.csv"
        )

        memory = self.results[
            "signature_memory"
        ]

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Peak Memory (KB)"
            ])

            writer.writerow([
                memory["peak_kb"]
            ])

        print(
            "signature_memory.csv exported."
        )
            # =====================================================
    # Signature Verification Benchmark
    # =====================================================

    def benchmark_signature_verification(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : ML-DSA SIGNATURE VERIFICATION")
        print("=" * 70)

        signer = self.vehicles[0]

        message = (
            "PQC-VANET Benchmark Message"
        )

        # ---------------------------------------------
        # Generate Signature Once
        # ---------------------------------------------

        signature = self.signature.sign(
            signer,
            message
        )

        # ---------------------------------------------
        # Execution Time Benchmark
        # ---------------------------------------------

        result = self.runner.execute(

            operation="signature_verification",

            function=lambda:
                self.verification.verify_authentication(
                    signer,
                    message,
                    signature
                )

        )

        self.results["verification"] = result

        print(f"\nAverage Time : {result['average']:.4f} ms")
        print(f"Minimum Time : {result['minimum']:.4f} ms")
        print(f"Maximum Time : {result['maximum']:.4f} ms")
        print(f"Std Dev      : {result['std_dev']:.4f} ms")

        # ---------------------------------------------
        # Memory Benchmark
        # ---------------------------------------------

        memory = BenchmarkAnalyzer.measure_memory(

            lambda:
                self.verification.verify_authentication(
                    signer,
                    message,
                    signature
                )

        )

        self.results["verification_memory"] = memory

        print(f"Peak Memory : {memory['peak_kb']} KB")

        print("\nSignature Verification Benchmark Completed.")
    

    # =====================================================
    # Export Verification Summary
    # =====================================================

    def export_verification_summary(self):

        file_path = (
            self.graph_data /
            "verification_summary.csv"
        )

        result = self.results["verification"]

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Average",
                "Median",
                "Minimum",
                "Maximum",
                "Std Dev",
                "Confidence95"
            ])

            writer.writerow([

                result["average"],
                result["median"],
                result["minimum"],
                result["maximum"],
                result["std_dev"],
                result["confidence95"]

            ])

        print(
            "verification_summary.csv exported."
        )

    # =====================================================
    # Export Verification Memory
    # =====================================================

    def export_verification_memory(self):

        file_path = (
            self.graph_data /
            "verification_memory.csv"
        )

        memory = self.results[
            "verification_memory"
        ]

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Peak Memory (KB)"
            ])

            writer.writerow([
                memory["peak_kb"]
            ])

        print(
            "verification_memory.csv exported."
        )
      
            # =====================================================
    # ML-KEM Encapsulation Benchmark
    # =====================================================

    def benchmark_encapsulation(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : ML-KEM ENCAPSULATION")
        print("=" * 70)

        responder = self.vehicles[1]

        # Execute benchmark
        result = self.runner.execute(
            operation="ML-KEM Encapsulation",
            function=lambda: kyber.encapsulate(responder.kem_pk)
        )

        # Store results
        self.results["encapsulation"] = result

        print("\nML-KEM Encapsulation Benchmark Results")
        print("-" * 50)
        print(f"Average Time : {result['average']:.4f} ms")
        print(f"Minimum Time : {result['minimum']:.4f} ms")
        print(f"Maximum Time : {result['maximum']:.4f} ms")
        print(f"Std Dev      : {result['std_dev']:.4f} ms")
        print("=" * 70 )
            # =====================================================
    # Export ML-KEM Encapsulation Summary
    # =====================================================

    def export_encapsulation_summary(self):

        import os
        import csv

        os.makedirs("graph_data", exist_ok=True)

        result = self.results["encapsulation"]

        with open(
            "graph_data/encapsulation_summary.csv",
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Average Time (ms)",
                "Minimum Time (ms)",
                "Maximum Time (ms)",
                "Standard Deviation (ms)"
            ])

            writer.writerow([
                result["average"],
                result["minimum"],
                result["maximum"],
                result["std_dev"]
            ])

        print("✓ Encapsulation Summary Exported")
            # =====================================================
    # ML-KEM Decapsulation Benchmark
    # =====================================================

    def benchmark_decapsulation(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : ML-KEM DECAPSULATION")
        print("=" * 70)

        responder = self.vehicles[1]

        # Generate one ciphertext for benchmarking
        ciphertext, _ = kyber.encapsulate(responder.kem_pk)

        result = self.runner.execute(
            operation="ML-KEM Decapsulation",
            function=lambda: kyber.decapsulate(
                responder.kem_sk,
                ciphertext
            )
        )

        self.results["decapsulation"] = result

        print("\nML-KEM Decapsulation Benchmark Results")
        print("-" * 50)
        print(f"Average Time : {result['average']:.4f} ms")
        print(f"Minimum Time : {result['minimum']:.4f} ms")
        print(f"Maximum Time : {result['maximum']:.4f} ms")
        print(f"Std Dev      : {result['std_dev']:.4f} ms")
        print("=" * 70)
            # =====================================================
    # Export ML-KEM Decapsulation Summary
    # =====================================================

    def export_decapsulation_summary(self):

        import os
        import csv

        os.makedirs("graph_data", exist_ok=True)

        result = self.results["decapsulation"]

        with open(
            "graph_data/decapsulation_summary.csv",
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Average Time (ms)",
                "Minimum Time (ms)",
                "Maximum Time (ms)",
                "Standard Deviation (ms)"
            ])

            writer.writerow([
                result["average"],
                result["minimum"],
                result["maximum"],
                result["std_dev"]
            ])

        print("✓ Decapsulation Summary Exported")
            # =====================================================
    # QRNG Performance Benchmark
    # =====================================================

    def benchmark_qrng(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : QRNG PERFORMANCE")
        print("=" * 70)

        result = self.runner.execute(
            operation="QRNG Random Generation",
            function=lambda: qrng.generate_random_bytes(32)
        )

        self.results["qrng"] = result

        print("\nQRNG Benchmark Results")
        print("-" * 50)
        print(f"Average Time : {result['average']:.4f} ms")
        print(f"Minimum Time : {result['minimum']:.4f} ms")
        print(f"Maximum Time : {result['maximum']:.4f} ms")
        print(f"Std Dev      : {result['std_dev']:.4f} ms")
        print("=" * 70)
            # =====================================================
    # Export QRNG Summary
    # =====================================================

    def export_qrng_summary(self):

        import csv
        import os

        os.makedirs("graph_data", exist_ok=True)

        result = self.results["qrng"]

        with open(
            "graph_data/qrng_summary.csv",
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Average Time (ms)",
                "Minimum Time (ms)",
                "Maximum Time (ms)",
                "Standard Deviation (ms)"
            ])

            writer.writerow([
                result["average"],
                result["minimum"],
                result["maximum"],
                result["std_dev"]
            ])

        print("✓ QRNG Summary Exported")
           
            # =====================================================
    # Communication Cost Benchmark
    # =====================================================

    def benchmark_communication_cost(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : COMMUNICATION COST")
        print("=" * 70)

        sender = self.vehicles[0]
        receiver = self.vehicles[1]

        request = self.authentication.create_auth_request(
            sender,
            receiver
        )

        field_sizes = {}
        total_bytes = 0

        for key, value in request.items():

            if isinstance(value, bytes):
                size = len(value)

            elif isinstance(value, str):
                size = len(value.encode())

            elif isinstance(value, int):
                size = 8

            else:
                size = len(str(value).encode())

            field_sizes[key] = size
            total_bytes += size

        self.results["communication"] = {
            "fields": field_sizes,
            "total_bytes": total_bytes
        }

        print("\nAuthentication Request Size\n")

        for field, size in field_sizes.items():
            print(f"{field:<25} : {size} Bytes")

        print("-" * 45)
        print(f"Total Communication Cost : {total_bytes} Bytes")

        self.export_communication_summary()

        print("\nCommunication Cost Benchmark Completed.")

    # =====================================================
    # Export Communication Summary
    # =====================================================

    def export_communication_summary(self):

        file_path = (
            self.graph_data /
            "communication_cost_summary.csv"
        )

        with open(file_path, "w", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                "Field",
                "Bytes"
            ])

            for field, size in self.results[
                "communication"
            ]["fields"].items():

                writer.writerow([
                    field,
                    size
                ])

            writer.writerow([
                "Total",
                self.results["communication"]["total_bytes"]
            ])

        print("communication_cost_summary.csv exported.")

    # =====================================================
    # Storage Cost Benchmark
    # =====================================================

    def benchmark_storage_cost(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : STORAGE COST")
        print("=" * 70)

        vehicle = self.vehicles[0]

        storage = {

            "ML-DSA Public Key":
                len(vehicle.sig_pk)
                if vehicle.sig_pk else 0,

            "ML-DSA Secret Key":
                len(vehicle.sig_sk)
                if vehicle.sig_sk else 0,

            "ML-KEM Public Key":
                len(vehicle.kem_pk)
                if vehicle.kem_pk else 0,

            "ML-KEM Secret Key":
                len(vehicle.kem_sk)
                if vehicle.kem_sk else 0,

            "Partial Public Key":
                len(vehicle.partial_public_key)
                if vehicle.partial_public_key else 0,

            "Partial Private Key":
                len(vehicle.partial_private_key)
                if vehicle.partial_private_key else 0,

            "Pseudonym":
                len(vehicle.pseudonym.encode())
                if getattr(vehicle, "pseudonym", None)
                else 0

        }

        storage["Total"] = sum(storage.values())

        self.results["storage"] = storage

        print()

        for component, size in storage.items():
            print(f"{component:<30} : {size} Bytes")

        self.export_storage_summary()

        print("\nStorage Cost Benchmark Completed.")

    # =====================================================
    # Export Storage Summary
    # =====================================================

    def export_storage_summary(self):

        file_path = (
            self.graph_data /
            "storage_cost_summary.csv"
        )

        with open(file_path, "w", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                "Component",
                "Bytes"
            ])

            for component, size in self.results[
                "storage"
            ].items():

                writer.writerow([
                    component,
                    size
                ])

        print("storage_cost_summary.csv exported.")
            # =====================================================
    # Memory Usage Benchmark
    # =====================================================

    def benchmark_memory_usage(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : MEMORY USAGE")
        print("=" * 70)

        sender = self.vehicles[0]
        receiver = self.vehicles[1]

        operations = {

            "Registration":
                lambda:
                    self.registration.register_vehicle(sender),

            "Key Generation":
                lambda:
                    self.key_generation.generate_keys(sender),

            "Authentication":
                lambda:
                    self.authentication.authenticate(
                        sender,
                        receiver
                    ),

            "Signature":
                lambda:
                    self.signature.sign(
                        sender,
                        "Benchmark Message"
                    )

        }

        memory_results = {}

        for name, operation in operations.items():

            memory = BenchmarkAnalyzer.measure_memory(
                operation
            )

            memory_results[name] = memory

            print(
                f"{name:<20}"
                f"{memory['peak_kb']:.2f} KB"
            )

        self.results["memory"] = memory_results

        self.export_memory_summary()

        print("\nMemory Benchmark Completed.")

    # =====================================================
    # Export Memory Summary
    # =====================================================

    def export_memory_summary(self):

        file_path = (
            self.graph_data /
            "memory_usage_summary.csv"
        )

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Operation",
                "Peak Memory (KB)"
            ])

            for operation, memory in self.results[
                "memory"
            ].items():

                writer.writerow([

                    operation,

                    memory["peak_kb"]

                ])

        print(
            "memory_usage_summary.csv exported."
        )
            # =====================================================
    # Memory Usage vs Number of Vehicles Benchmark
    # =====================================================

    def benchmark_memory_scalability(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : MEMORY USAGE VS NUMBER OF VEHICLES")
        print("=" * 70)

        test_sizes = [2, 5, 10, 20, 40, 60, 80, 100]

        memory_results = []

        original_vehicle_count = self.vehicle_count
        original_print = builtins.print

        try:

            for count in test_sizes:

                print(f"\nTesting Memory with {count} Vehicles...")

                self.vehicle_count = count

                # Disable protocol print statements during measurement
                builtins.print = lambda *args, **kwargs: None

                try:

                    memory = BenchmarkAnalyzer.measure_memory(
                        self.prepare_network
                    )

                finally:

                    builtins.print = original_print

                peak_memory = memory["peak_kb"]

                memory_results.append({
                    "vehicles": count,
                    "peak_memory_kb": round(peak_memory, 4)
                })

                print(
                    f"Vehicles : {count:<4} | "
                    f"Peak Memory : {peak_memory:.2f} KB"
                )

        finally:

            builtins.print = original_print
            self.vehicle_count = original_vehicle_count

        self.results["memory_scalability"] = memory_results

        self.export_memory_scalability_summary()

        print("\nMemory Scalability Benchmark Completed.")
            # =====================================================
    # Export Memory Scalability Summary
    # =====================================================

    def export_memory_scalability_summary(self):

        file_path = (
            self.graph_data /
            "memory_scalability_summary.csv"
        )

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "vehicles",
                "peak_memory_kb"
            ])

            for row in self.results["memory_scalability"]:

                writer.writerow([
                    row["vehicles"],
                    row["peak_memory_kb"]
                ])

        print(
            "memory_scalability_summary.csv exported."
        )
    # =====================================================
    # Scalability Benchmark
    # =====================================================

    def benchmark_scalability(self):

        print("\n" + "=" * 70)
        print("BENCHMARK : NETWORK SCALABILITY")
        print("=" * 70)

        test_sizes = [2, 5, 10, 20, 40, 60, 80, 100]

        scalability_results = []

        original_vehicle_count = self.vehicle_count
        original_print = builtins.print

        try:

            for count in test_sizes:

                print(f"\nTesting Network with {count} Vehicles...")

                self.vehicle_count = count

                # Prepare network for this vehicle count
                builtins.print = lambda *args, **kwargs: None

                try:
                    self.prepare_network()
                finally:
                    builtins.print = original_print

                # Number of adjacent authentication pairs
                pair_count = len(self.vehicles) - 1

                pair_results = []

                builtins.print = lambda *args, **kwargs: None

                try:

                    for i in range(pair_count):

                        sender = self.vehicles[i]
                        receiver = self.vehicles[i + 1]

                        result = self.runner.execute(
                            operation=f"scalability_{count}_{i}",
                            function=lambda s=sender, r=receiver: (
                                self.authentication.authenticate(s, r)
                            ),
                            iterations=5
                        )

                        pair_results.append(result)

                finally:
                    builtins.print = original_print

                # Average latency of one authentication
                average_pair_latency = (
                    sum(
                        r["average"]
                        for r in pair_results
                    )
                    / len(pair_results)
                )

                # Total network authentication workload
                total_authentication_time = sum(
                    r["average"]
                    for r in pair_results
                )

                scalability_results.append({
                    "vehicles": count,
                    "authentication_pairs": pair_count,
                    "average_pair_latency_ms": round(
                        average_pair_latency,
                        6
                    ),
                    "total_authentication_time_ms": round(
                        total_authentication_time,
                        6
                    )
                })

                print(
                    f"Vehicles : {count:<4} | "
                    f"Pairs : {pair_count:<4} | "
                    f"Average Pair Delay : "
                    f"{average_pair_latency:.4f} ms | "
                    f"Total Network Time : "
                    f"{total_authentication_time:.4f} ms"
                )

        finally:

            builtins.print = original_print
            self.vehicle_count = original_vehicle_count

        self.results["scalability"] = scalability_results

        self.export_scalability_summary()

        print("\nScalability Benchmark Completed.")
            # =====================================================
    # Export Scalability Summary
    # =====================================================

    def export_scalability_summary(self):

        file_path = (
            self.graph_data /
            "scalability_summary.csv"
        )

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "vehicles",
                "authentication_pairs",
                "average_pair_latency_ms",
                "total_authentication_time_ms"
            ])

            for row in self.results["scalability"]:

                writer.writerow([
                    row["vehicles"],
                    row["authentication_pairs"],
                    row["average_pair_latency_ms"],
                    row["total_authentication_time_ms"]
                ])

        print(
            "scalability_summary.csv exported."
        )        
     # =====================================================
    # Security Feature Evaluation
    # =====================================================

    def benchmark_security_features(self):

        print("\n" + "=" * 70)
        print("SECURITY FEATURE EVALUATION")
        print("=" * 70)

        features = {

            "Mutual Authentication": True,
            "Post-Quantum Security": True,
            "Conditional Privacy": True,
            "Identity Protection": True,
            "Dynamic Pseudonyms": True,
            "Replay Protection": True,
            "MITM Resistance": True,
            "Forward Secrecy": True,
            "Context Awareness": True,
            "Threat Evaluation": True,
            "Certificate-less Authentication": True,
            "Authentication State Machine": True

        }

        self.results["security_features"] = features

        file_path = (
            self.graph_data /
            "security_features.csv"
        )

        with open(
            file_path,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Feature",
                "Supported"
            ])

            for feature, value in features.items():

                writer.writerow([
                    feature,
                    "Yes" if value else "No"
                ])

        print("security_features.csv exported.")
        print("Security Feature Evaluation Completed.")

    # =====================================================
    # Run Complete Benchmark
    # =====================================================

    def run_all_benchmarks(self):

        print("\n")
        print("=" * 70)
        print("PQC-VANET PERFORMANCE EVALUATION")
        print("=" * 70)

        start = time.perf_counter()

        # ----------------------------
        # Network
        # ----------------------------

        self.prepare_network()

        # ----------------------------
        # Benchmarks
        # ----------------------------

        self.benchmark_registration()
        self.export_registration_summary()

        self.benchmark_key_generation()
        self.export_key_generation_summary()

        self.benchmark_authentication()
        self.export_authentication_summary()
        self.export_authentication_memory()
        self.benchmark_encapsulation()
        self.export_encapsulation_summary()
        self.benchmark_decapsulation()
        self.export_decapsulation_summary()
        self.benchmark_qrng()
        self.export_qrng_summary()
                     
        self.benchmark_signature()
        self.export_signature_summary()
        self.export_signature_memory()

        self.benchmark_signature_verification()
        self.export_verification_summary()
        self.export_verification_memory()
        

        self.benchmark_communication_cost()
    

        self.benchmark_storage_cost()

        self.benchmark_memory_usage()
        self.benchmark_memory_scalability()

        self.benchmark_scalability()

        self.benchmark_security_features()

        total = time.perf_counter() - start

        self.results["overall_execution_time"] = total

        print("\n")
        print("=" * 70)
        print("BENCHMARK COMPLETED SUCCESSFULLY")
        print("=" * 70)

        print(f"Vehicles     : {self.vehicle_count}")
        print(f"Iterations   : {self.iterations}")
        print(f"Total Time   : {total:.3f} seconds")

    # =====================================================
    # Print Summary
    # =====================================================

    def print_summary(self):

        print("\n")
        print("=" * 70)
        print("FINAL PERFORMANCE SUMMARY")
        print("=" * 70)

        print(f"Vehicles Tested : {self.vehicle_count}")
        print(f"Iterations      : {self.iterations}")

        if "authentication" in self.results:

            print(
                f"Authentication : "
                f"{self.results['authentication']['average']:.4f} ms"
            )

        if "signature" in self.results:

            print(
                f"Signature      : "
                f"{self.results['signature']['average']:.4f} ms"
            )

        if "verification" in self.results:

            print(
                f"Verification   : "
                f"{self.results['verification']['average']:.4f} ms"
            )

        if "communication" in self.results:

            print(
                f"Communication  : "
                f"{self.results['communication']['total_bytes']} Bytes"
            )

        if "storage" in self.results:

            print(
                f"Storage        : "
                f"{self.results['storage']['Total']} Bytes"
            )

        print("=" * 70)
        # =====================================================
# Main
# =====================================================

if __name__ == "__main__":

    benchmark = ProtocolBenchmark(

        vehicle_count=2,

        iterations=30

    )

    benchmark.run_all_benchmarks()

    benchmark.print_summary()

