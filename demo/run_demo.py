"""
run_demo.py — CLI entry point for all SDVN-Security-CIA-Project demonstrations.

Usage:
    python demo/run_demo.py                        # runs all scenarios in sequence
    python demo/run_demo.py --scenario <name>      # runs one specific scenario

Available scenario names:
    confidentiality, integrity, authentication, non_repudiation, availability
"""

import argparse
import sys

from demo.demo_scenarios import (
    demo_authentication,
    demo_availability,
    demo_confidentiality,
    demo_integrity,
    demo_non_repudiation,
)

SCENARIOS: dict[str, callable] = {
    "confidentiality": demo_confidentiality,
    "integrity": demo_integrity,
    "authentication": demo_authentication,
    "non_repudiation": demo_non_repudiation,
    "availability": demo_availability,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="SDVN-Security-CIA-Project demo runner")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS),
        help="Run a single scenario instead of all",
    )
    args = parser.parse_args()

    targets = {args.scenario: SCENARIOS[args.scenario]} if args.scenario else SCENARIOS

    for name, fn in targets.items():
        print(f"\n{'=' * 60}")
        print(f"  Scenario: {name.upper().replace('_', ' ')}")
        print(f"{'=' * 60}")
        fn()

    print("\nAll demos complete.")


if __name__ == "__main__":
    main()
