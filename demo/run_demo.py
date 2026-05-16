"""
demo/run_demo.py — Master CLI entry point for SDVN-Security-CIA-Project

Usage
-----
    # Run every scenario in order (recommended for a full course demo)
    python demo/run_demo.py

    # Run one specific security property
    python demo/run_demo.py --scenario confidentiality
    python demo/run_demo.py --scenario integrity
    python demo/run_demo.py --scenario authentication
    python demo/run_demo.py --scenario non_repudiation
    python demo/run_demo.py --scenario availability

    # Run all five attack simulations (no controller required)
    python demo/run_demo.py --scenario attacks

    # Run the live Vehicle ↔ Controller socket demo (requires two terminals)
    #   Terminal 1:  python demo/run_demo.py --live-controller
    #   Terminal 2:  python demo/run_demo.py --live-vehicle
    python demo/run_demo.py --live-controller
    python demo/run_demo.py --live-vehicle [--vehicle-id V001] [--metrics 3]
"""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows so Unicode separators / arrows in demo output
# are not rejected by the default cp1252 console codec.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
elif sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Ensure the project root is on sys.path so that `core`, `nodes`, `attacks`,
# and `demo` are all importable regardless of how this script is invoked
# (e.g. `python demo/run_demo.py` sets demo/ as cwd, not the project root).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ── Scenario registry ─────────────────────────────────────────────────────────

SCENARIOS: dict[str, tuple[str, callable]] = {
    "confidentiality":  ("CONFIDENTIALITY  — AES-256-GCM",   None),
    "integrity":        ("INTEGRITY        — HMAC + HashChain", None),
    "authentication":   ("AUTHENTICATION   — ECDH P-256",    None),
    "non_repudiation":  ("NON-REPUDIATION  — RSA-2048 PSS",  None),
    "availability":     ("AVAILABILITY     — Sessions + Ledger", None),
    "attacks":          ("ATTACK SIMULATOR — All 5 Attacks",  None),
}

# Lazy-load to avoid circular imports at module level
def _load_scenarios() -> None:
    from demo.demo_scenarios import (
        demo_attacks,
        demo_authentication,
        demo_availability,
        demo_confidentiality,
        demo_integrity,
        demo_non_repudiation,
    )
    SCENARIOS["confidentiality"] = (SCENARIOS["confidentiality"][0], demo_confidentiality)
    SCENARIOS["integrity"]       = (SCENARIOS["integrity"][0],       demo_integrity)
    SCENARIOS["authentication"]  = (SCENARIOS["authentication"][0],  demo_authentication)
    SCENARIOS["non_repudiation"] = (SCENARIOS["non_repudiation"][0], demo_non_repudiation)
    SCENARIOS["availability"]    = (SCENARIOS["availability"][0],    demo_availability)
    SCENARIOS["attacks"]         = (SCENARIOS["attacks"][0],         demo_attacks)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _header() -> None:
    w = 60
    print(f"\n{Fore.CYAN}{'=' * w}")
    print(f"  {'SDVN-Security-CIA-Project  --  Full Demo':^{w-4}}")
    print(f"  {'Confidentiality  Integrity  Auth  Non-Rep  Avail':^{w-4}}")
    print(f"{'=' * w}{Style.RESET_ALL}\n")


def _run_scenario(key: str) -> None:
    label, fn = SCENARIOS[key]
    w = 60
    print(f"\n{Fore.CYAN}{'=' * w}")
    print(f"  {label}")
    print(f"{'=' * w}{Style.RESET_ALL}")
    fn()
    print()


# ── Live socket demo ──────────────────────────────────────────────────────────

def _run_live_controller(host: str, port: int) -> None:
    """Start the SDN Controller and block until Ctrl-C."""
    from nodes.controller_node import ControllerNode

    print(f"\n{Fore.CYAN}[DEMO] Starting SDN Controller on {host}:{port}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}       Press Ctrl-C to stop.{Style.RESET_ALL}\n")
    ctrl = ControllerNode(host=host, port=port)
    ctrl.run()


def _run_live_vehicle(
    host: str,
    port: int,
    vehicle_id: str,
    n_metrics: int,
) -> None:
    """Connect a VehicleNode, do a full handshake, send beacons and metrics."""
    from nodes.vehicle_node import VehicleNode

    print(f"\n{Fore.CYAN}[DEMO] Starting Vehicle Node '{vehicle_id}'{Style.RESET_ALL}\n")

    vehicle = VehicleNode(vehicle_id=vehicle_id, host=host, port=port)

    try:
        # ── Step 1: TCP connect ──────────────────────────────────────────
        vehicle.connect()
        time.sleep(0.1)

        # ── Step 2: ECDH key exchange ────────────────────────────────────
        vehicle.perform_key_exchange()
        time.sleep(0.2)

        # ── Step 3: Send 2 beacons ───────────────────────────────────────
        vehicle.send_beacon(position=(51.5074, -0.1278), velocity=60.0)
        time.sleep(0.2)
        vehicle.send_beacon(position=(51.5080, -0.1282), velocity=62.5)
        time.sleep(0.2)

        # ── Step 4: Send N metrics ───────────────────────────────────────
        metrics = [
            {"speed_kmh": 60 + i * 3, "gps": [51.5074 + i * 0.001, -0.1278],
             "fuel_pct": 80 - i * 2, "engine_temp_c": 90 + i}
            for i in range(n_metrics)
        ]
        for m in metrics:
            vehicle.send_metric(m)
            time.sleep(0.3)

    finally:
        vehicle.close()

    print(f"\n{Fore.GREEN}[DEMO] Vehicle '{vehicle_id}' session complete.{Style.RESET_ALL}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SDVN-Security-CIA-Project demo runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS),
        metavar="SCENARIO",
        help=(
            "Run one scenario: "
            + ", ".join(SCENARIOS)
        ),
    )
    mode.add_argument(
        "--live-controller",
        action="store_true",
        help="Start the SDN Controller node (blocks until Ctrl-C)",
    )
    mode.add_argument(
        "--live-vehicle",
        action="store_true",
        help="Start a Vehicle node and connect to the running controller",
    )

    parser.add_argument("--host",       default="127.0.0.1", help="Controller host (default: 127.0.0.1)")
    parser.add_argument("--port",       default=9000, type=int, help="Controller port (default: 9000)")
    parser.add_argument("--vehicle-id", default="V001", help="Vehicle pseudonym (default: V001)")
    parser.add_argument("--metrics",    default=3, type=int, help="Number of metric messages to send (default: 3)")

    args = parser.parse_args()

    # ── Live modes ────────────────────────────────────────────────────────
    if args.live_controller:
        _run_live_controller(args.host, args.port)
        return

    if args.live_vehicle:
        _run_live_vehicle(args.host, args.port, args.vehicle_id, args.metrics)
        return

    # ── Scenario modes ────────────────────────────────────────────────────
    _load_scenarios()
    _header()

    if args.scenario:
        _run_scenario(args.scenario)
    else:
        # Run all five security-property scenarios, then all five attacks
        for key in SCENARIOS:
            _run_scenario(key)

    print(f"{Fore.GREEN}{'═'*60}")
    print(f"  All demos complete.")
    print(f"{'═'*60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
