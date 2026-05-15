# SDVN-Security-CIA-Project

A professional implementation of a **secure communication scheme** between two untrusted network
parties — a **Vehicle Node** and an **SDN Controller** — demonstrating all five core security
properties required by the Information Security course.

Inspired by the author's Final Year Project on **Software-Defined Vehicular Networks (SIGMA-V)**,
this project models the real-world challenge of authenticating and securing dynamic V2I
(Vehicle-to-Infrastructure) communication in an untrusted SDN environment.

---

## Security Properties Demonstrated

| Property | Mechanism | Module |
|---|---|---|
| **Confidentiality** | AES-256-GCM symmetric encryption of all payloads | `core/aes_gcm_encrypt.py` |
| **Integrity** | HMAC-SHA256 message authentication + SHA-256 hash chains | `core/hmac_auth.py`, `core/hash_chain.py` |
| **Authentication** | ECDH key exchange + HMAC session tokens | `core/key_exchange.py`, `core/session_manager.py` |
| **Non-Repudiation** | RSA-2048 digital signatures on all critical messages | `core/rsa_signatures.py` |
| **Availability** | Attack simulation + detection logic; blockchain audit ledger | `attacks/attack_simulator.py`, `core/blockchain_ledger.py` |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  SDVN Secure Channel                        │
│                                                             │
│  ┌──────────────┐    Encrypted + Signed Packets    ┌──────────────────┐  │
│  │ Vehicle Node │ ──────────────────────────────► │ SDN Controller   │  │
│  │              │ ◄────────────────────────────── │                  │  │
│  │  [BEACON]    │    TLS-grade AES-GCM tunnel      │  [METRIC ACK]    │  │
│  │  [METRIC]    │                                  │  [LEDGER UPDATE] │  │
│  └──────────────┘                                  └──────────────────┘  │
│         │                                                   │            │
│         └──────────────┬────────────────────────────────────┘            │
│                        │                                                 │
│             ┌──────────▼──────────┐                                      │
│             │  Blockchain Ledger  │  (tamper-evident audit trail)         │
│             └─────────────────────┘                                      │
└─────────────────────────────────────────────────────────────────────────┘

Message Flow:
  1. Vehicle broadcasts BEACON  →  Controller receives + verifies HMAC
  2. ECDH KEY_EXCHANGE          →  Both derive shared session key
  3. Vehicle sends METRIC data  →  AES-GCM encrypted, RSA-signed
  4. Controller responds        →  HMAC-validated, logged to ledger
  5. Attack simulator fires     →  Replay / MITM / flood detected + blocked
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/sahan411/SDVN-Security-CIA-porject.git
cd SDVN-Security-CIA-porject

# Create and activate a virtual environment (recommended)
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Demo

```bash
# Full interactive demo (all security properties)
python demo/run_demo.py

# Run a specific scenario
python demo/run_demo.py --scenario confidentiality
python demo/run_demo.py --scenario integrity
python demo/run_demo.py --scenario authentication
python demo/run_demo.py --scenario non_repudiation
python demo/run_demo.py --scenario availability

# Run the attack simulation
python attacks/attack_simulator.py
```

---

## Demo Scenarios

| Scenario | What It Shows |
|---|---|
| `confidentiality` | Encrypts a vehicle metric with AES-256-GCM; shows ciphertext vs plaintext |
| `integrity` | Mutates a packet in transit; HMAC check catches the tampering |
| `authentication` | Full ECDH handshake between Vehicle and Controller |
| `non_repudiation` | RSA-signs a METRIC message; verifies signature on Controller side |
| `availability` | Simulates replay attack and flood; detection layer blocks both |

---

## Project Structure

```
SDVN-Security-CIA-Project/
├── core/                   # Cryptographic primitives and shared state
│   ├── network_config.py   # Constants, message formats, shared keys
│   ├── aes_gcm_encrypt.py  # AES-256-GCM encryption/decryption
│   ├── hmac_auth.py        # HMAC-SHA256 message authentication
│   ├── hash_chain.py       # Hash chain for message ordering/integrity
│   ├── key_exchange.py     # ECDH key exchange protocol
│   ├── session_manager.py  # Session token lifecycle
│   ├── rsa_signatures.py   # RSA-2048 sign/verify
│   └── blockchain_ledger.py# Append-only audit log
├── nodes/
│   ├── vehicle_node.py     # Vehicle party — sends beacons and metrics
│   └── controller_node.py  # SDN Controller — receives, validates, logs
├── attacks/
│   └── attack_simulator.py # Replay, MITM, and flood attack simulation
└── demo/
    ├── run_demo.py         # CLI entry point for all demos
    └── demo_scenarios.py   # Individual scenario implementations
```

---

## Tech Stack

- **Python 3.10+**
- [`cryptography`](https://cryptography.io) — AES-GCM, ECDH, HMAC, RSA (high-level Hazmat API)
- [`pycryptodome`](https://pycryptodome.readthedocs.io) — supplementary crypto primitives
- [`colorama`](https://pypi.org/project/colorama/) — colour-coded terminal output for demo clarity
- Standard library: `hashlib`, `hmac`, `dataclasses`, `enum`, `socket`, `logging`

---

## Connection to FYP (SIGMA-V)

This project directly implements the **security layer** of the SIGMA-V architecture studied in the
author's Final Year Project on Software-Defined Vehicular Networks. In SIGMA-V, an SDN Controller
manages routing and flow rules for a dynamic fleet of vehicle nodes over an untrusted wireless
medium. The five security properties demonstrated here map directly to the threat model and
security requirements defined in the SIGMA-V specification:

- **Confidentiality** prevents passive eavesdropping on V2I telemetry.
- **Integrity** ensures flow-rule updates cannot be silently modified.
- **Authentication** prevents rogue vehicles from injecting false metrics.
- **Non-Repudiation** provides forensic accountability for controller decisions.
- **Availability** protects the control plane from denial-of-service and replay attacks.

---

## Author

Built for the **Information Security** university course module.
