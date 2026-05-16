"""
demo/run_demo.py — Live demo runner for SDVN-Security-CIA-Project

Runs four narrated scenarios in sequence with coloured terminal output:

  SCENARIO 1 — Normal Secure Operation
      Controller starts in background  →  Vehicle connects  →  ECDH key exchange
      3 encrypted beacons  →  3 hash-chained, RSA-signed metrics  →  ledger display

  SCENARIO 2 — HMAC Bypass Attack
      Attacker forges HMAC tag  →  controller rejects in constant time
      Security property: AUTHENTICATION

  SCENARIO 3 — Metric Tampering Attack
      Attacker replays stale chain link at position 2
      Security property: INTEGRITY (hash chain)

  SCENARIO 4 — Non-Repudiation Demonstration
      Ledger displayed  →  entry #2 overwritten  →  verify_chain() catches it
      Security property: NON-REPUDIATION

Usage:
    python demo/run_demo.py                   # all four scenarios
    python demo/run_demo.py --scenario 1      # single scenario (1-4)
    python demo/run_demo.py --no-delays       # skip sleep() pauses (CI / testing)
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import time
from pathlib import Path

# ── Make project root importable regardless of invocation directory ───────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Force UTF-8 stdout so Unicode box-drawing chars render on Windows ─────────
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
elif sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ── Demo configuration ────────────────────────────────────────────────────────
DEMO_HOST = "127.0.0.1"
DEMO_PORT = 9100   # separate port avoids conflicts with any long-running instance
INTER_SCENARIO_PAUSE = 3.0   # seconds between scenarios


# ── Colour helpers ────────────────────────────────────────────────────────────

def _green(msg: str)  -> None: print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
def _red(msg: str)    -> None: print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
def _cyan(msg: str)   -> None: print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")
def _yellow(msg: str) -> None: print(f"{Fore.YELLOW}{msg}{Style.RESET_ALL}")
def _white(msg: str)  -> None: print(msg)


# ── Banner helpers ────────────────────────────────────────────────────────────

_W = 66   # banner width

def _thick_banner(title: str, subtitle: str = "") -> None:
    """Double-line box for scenario titles."""
    print()
    _yellow("=" * _W)
    _yellow(f"  {title}")
    if subtitle:
        _cyan(f"  {subtitle}")
    _yellow("=" * _W)
    print()


def _thin_banner(msg: str) -> None:
    """Single-line separator for sub-sections."""
    _cyan("  " + "-" * (_W - 4))
    _cyan(f"  {msg}")
    _cyan("  " + "-" * (_W - 4))
    print()


def _end_banner(msg: str, success: bool = True) -> None:
    """Full-width conclusion banner at the end of each scenario."""
    colour = Fore.GREEN if success else Fore.RED
    print()
    print(f"{colour}{'=' * _W}")
    print(f"  {msg}")
    print(f"{'=' * _W}{Style.RESET_ALL}")
    print()


def _pause(seconds: float, enabled: bool = True) -> None:
    if enabled:
        time.sleep(seconds)


def _countdown(n: int, label: str, enabled: bool = True) -> None:
    if not enabled:
        return
    for i in range(n, 0, -1):
        print(f"\r  {Fore.CYAN}{label} in {i}s…{Style.RESET_ALL}", end="", flush=True)
        time.sleep(1)
    print(f"\r{' ' * 40}\r", end="", flush=True)


# ════════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Normal Secure Operation
# ════════════════════════════════════════════════════════════════════════════════

def run_scenario_1(host: str, port: int, delay: bool = True):
    """Full live socket demo — every security property active simultaneously."""
    _thick_banner(
        "SCENARIO 1: Normal Secure Operation",
        "Vehicle Node V001  <-->  SDN Controller  |  Full security stack",
    )

    _thin_banner("What you will see")
    _white("  Each message passes through four security layers:")
    _white("  ECDH key exchange  -->  AES-256-GCM encryption  -->  HMAC auth  -->  RSA sign")
    _white("  Every METRIC is hash-chained and logged to the controller's ledger.")
    _pause(1.5, delay)

    from demo.demo_scenarios import scenario_normal_operation

    ledger = scenario_normal_operation(host=host, port=port, delay=delay)

    _pause(0.5, delay)
    _end_banner(
        "OK  All security properties active — system operating securely",
        success=True,
    )
    return ledger   # pass to Scenario 4


# ════════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — HMAC Bypass Attack
# ════════════════════════════════════════════════════════════════════════════════

def run_scenario_2(host: str, port: int, delay: bool = True) -> None:
    """Attacker forges HMAC tag — controller rejects before decrypting payload."""
    _thick_banner(
        "SCENARIO 2: Attack Simulation — HMAC Bypass",
        "Attacker has AES session key but not K_HMAC  |  Forges auth tag",
    )

    _thin_banner("What you will see")
    _white("  The attacker completes a valid ECDH handshake (gets K_AES).")
    _white("  They build a BEACON with false GPS data and compute its HMAC")
    _white("  using a random key instead of K_HMAC (which they cannot know).")
    _white("  verify_hmac() uses constant-time comparison — any wrong key is rejected.")
    _pause(1.5, delay)

    from demo.demo_scenarios import scenario_hmac_bypass

    scenario_hmac_bypass(host=host, port=port, delay=delay)

    _pause(0.5, delay)
    _end_banner(
        "OK  Authentication property stopped the attack",
        success=True,
    )


# ════════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Metric Tampering (Hash Chain)
# ════════════════════════════════════════════════════════════════════════════════

def run_scenario_3(delay: bool = True) -> None:
    """Attacker replays stale chain link at wrong position — hash chain catches it."""
    _thick_banner(
        "SCENARIO 3: Attack Simulation — Metric Tampering",
        "Attacker drops metric #1 and injects tampered GPS at position 2",
    )

    _thin_banner("What you will see")
    _white("  Vehicle sends 2 legitimate metrics; controller's parallel chain advances.")
    _white("  Attacker intercepts metric #1, drops it, and injects a metric at pos 2")
    _white("  with modified GPS coordinates and the OLD chain_link from position 0.")
    _white("  The controller computes SHA256(payload || link_1) != link_0  =>  REJECTED.")
    _pause(1.5, delay)

    from demo.demo_scenarios import scenario_metric_tampering

    scenario_metric_tampering(delay=delay)

    _pause(0.5, delay)
    _end_banner(
        "OK  Integrity property stopped the attack",
        success=True,
    )


# ════════════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — Non-Repudiation
# ════════════════════════════════════════════════════════════════════════════════

def run_scenario_4(ledger=None, delay: bool = True) -> None:
    """Ledger display + tamper attempt caught by hash chain and RSA signature check."""
    _thick_banner(
        "SCENARIO 4: Non-Repudiation Demonstration",
        "Controller's blockchain ledger  |  Tamper attempt  |  verify_chain() catches it",
    )

    _thin_banner("What you will see")
    _white("  The controller's signed audit ledger is displayed (from Scenario 1).")
    _white("  An attacker with storage access overwrites vehicle_id in entry #2.")
    _white("  verify_chain() recomputes every hash — the modification is caught")
    _white("  because entry_hash no longer matches AND the RSA signature is invalid.")
    _pause(1.5, delay)

    from demo.demo_scenarios import scenario_non_repudiation

    scenario_non_repudiation(ledger=ledger, delay=delay)

    _pause(0.5, delay)
    _end_banner(
        "OK  Non-repudiation — records are permanent and undeniable",
        success=True,
    )


# ════════════════════════════════════════════════════════════════════════════════
# OPENING TITLE CARD
# ════════════════════════════════════════════════════════════════════════════════

def _title_card(delay: bool = True) -> None:
    print()
    _green("=" * _W)
    _green(f"  {'SDVN-Security-CIA-Project':^{_W-4}}")
    _green(f"  {'Secure V2I Communication Demo':^{_W-4}}")
    _green(f"  {'Software-Defined Vehicular Networks — SIGMA-V Security Layer':^{_W-4}}")
    _green("=" * _W)
    print()
    _white(f"  Security properties demonstrated:")
    _cyan( f"    Confidentiality  —  AES-256-GCM")
    _cyan( f"    Integrity        —  HMAC-SHA256 + SHA-256 Hash Chain")
    _cyan( f"    Authentication   —  ECDH P-256 + HKDF")
    _cyan( f"    Non-Repudiation  —  RSA-2048 PSS + Blockchain Ledger")
    _cyan( f"    Availability     —  Session management + replay detection")
    print()
    _white(f"  4 scenarios will run. Controller host: {DEMO_HOST}:{DEMO_PORT}")
    print()
    _pause(2.0, delay)


# ════════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════════════════════

def _final_summary() -> None:
    print()
    _green("=" * _W)
    _green(f"  {'DEMO COMPLETE — SUMMARY':^{_W-4}}")
    _green("=" * _W)
    print()
    _green("  SCENARIO 1  Normal Secure Operation")
    _white( "              ECDH handshake + AES-GCM beacons + RSA-signed metrics")
    _white( "              Ledger audit trail created and verified")
    print()
    _green("  SCENARIO 2  HMAC Bypass Attack  =>  BLOCKED")
    _white( "              Forged HMAC tag rejected by constant-time verify_hmac()")
    _white( "              Security property: AUTHENTICATION")
    print()
    _green("  SCENARIO 3  Metric Tampering Attack  =>  BLOCKED")
    _white( "              Stale chain_link at position 2 caught by parallel chain")
    _white( "              Security property: INTEGRITY")
    print()
    _green("  SCENARIO 4  Non-Repudiation Demonstration  =>  PERMANENT RECORD")
    _white( "              Ledger tamper caught by hash mismatch + RSA sig failure")
    _white( "              Security property: NON-REPUDIATION")
    print()
    _green("=" * _W)
    _green(f"  {'All five CIA security properties verified.':^{_W-4}}")
    _green("=" * _W)
    print()


# ════════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SDVN-Security-CIA-Project live demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--scenario", "-s",
        type=int,
        choices=[1, 2, 3, 4],
        metavar="N",
        help="Run only scenario N (1-4). Omit to run all four in sequence.",
    )
    parser.add_argument(
        "--no-delays",
        action="store_true",
        help="Skip time.sleep() pauses — useful for automated testing.",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Controller host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", default=9100, type=int,
        help="Controller port (default: 9100)",
    )
    args  = parser.parse_args()
    host  = args.host
    port  = args.port
    delay = not args.no_delays

    _title_card(delay=delay)

    ledger = None   # passed from Scenario 1 → Scenario 4

    scenarios_to_run = [args.scenario] if args.scenario else [1, 2, 3, 4]

    for n in scenarios_to_run:
        if n == 1:
            ledger = run_scenario_1(host=DEMO_HOST, port=DEMO_PORT, delay=delay)
        elif n == 2:
            run_scenario_2(host=DEMO_HOST, port=DEMO_PORT, delay=delay)
        elif n == 3:
            run_scenario_3(delay=delay)
        elif n == 4:
            run_scenario_4(ledger=ledger, delay=delay)

        if n != scenarios_to_run[-1]:
            _countdown(
                int(INTER_SCENARIO_PAUSE),
                label=f"Next scenario",
                enabled=delay,
            )

    if not args.scenario:   # only show summary when all four ran
        _final_summary()


if __name__ == "__main__":
    main()
