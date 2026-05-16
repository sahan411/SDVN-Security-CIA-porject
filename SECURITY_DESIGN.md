# SECURITY_DESIGN.md — SDVN-Security-CIA-Project

A complete reference for the security architecture, threat model, algorithm
choices, known limitations, and mapping to the SIGMA-V FYP equations.

---

## 1. Threat Model

### Actors

| Actor | Description |
|---|---|
| **Vehicle Node** | Legitimate sender of BEACON and METRIC messages. Holds an ephemeral ECDH keypair and a long-term RSA keypair per session. |
| **SDN Controller** | Trusted receiver. Maintains session state, verifies all messages, and maintains the blockchain ledger. |
| **Passive Attacker (Eavesdropper)** | Can capture all packets on the wireless channel. Goal: read plaintext metric data (GPS, speed, fuel). |
| **Active Attacker (MITM)** | Can intercept, modify, drop, replay, and inject packets. May complete a valid ECDH handshake but does NOT hold the legitimate vehicle's RSA private key. |
| **Insider / Storage Attacker** | Has direct read-write access to the controller's ledger storage (e.g. via a compromised disk). Goal: silently alter or delete audit records. |

### Attacker Capabilities

- **Network access**: Full control of the channel — intercept, replay, modify, drop, inject.
- **Computational**: Cannot break AES-256-GCM, ECDH P-256 ECDLP, HMAC-SHA256, RSA-2048, or SHA-256 in polynomial time (standard cryptographic assumptions).
- **Key knowledge**: Attacker does NOT know `K_HMAC` (derived from ECDH shared secret Z), the vehicle's RSA private key, or the controller's RSA private key.
- **Timing**: Attacker can observe response latency but `hmac.compare_digest()` eliminates timing side-channels on HMAC comparison.

### Assets to Protect

| Asset | Threat | Property |
|---|---|---|
| METRIC payload contents | Eavesdropping | Confidentiality |
| METRIC payload field values | In-transit modification | Integrity |
| Message ordering | Dropped/reordered packets | Integrity (hash chain) |
| Sender identity | Impersonation | Authentication |
| Audit trail | Retroactive denial, tampering | Non-Repudiation |
| Controller availability | Session flood, resource exhaustion | Availability |

---

## 2. Security Properties and Mechanisms

### 2.1 Confidentiality — AES-256-GCM

Every BEACON and METRIC payload is encrypted with `AESGCM(K_AES)` before
transmission. The ciphertext reveals nothing about the plaintext to anyone
who does not hold `K_AES`.

`K_AES` is never transmitted; it is independently derived on both sides from
the ECDH shared secret via HKDF (see §4.2).

**File**: [core/aes_gcm_encrypt.py](core/aes_gcm_encrypt.py)

### 2.2 Integrity — HMAC-SHA256 + SHA-256 Hash Chain

**Per-message integrity**: `HMAC-SHA256(K_HMAC, payload_bytes)` is computed on
the sender side and verified on the receiver before the plaintext is trusted.
Any single-bit change to the payload produces a completely different tag
(SHA-256 avalanche effect).

**Sequence integrity**: A SHA-256 hash chain links every METRIC to its
predecessor: `H[i] = SHA256(payload[i] || H[i-1])`. The controller maintains
a parallel chain and compares expected vs. received links. This detects:

- **Dropped messages** — chain position mismatch
- **Reordered messages** — SHA-256 of wrong predecessor
- **Tampered payloads** — SHA-256 of modified message differs

**Files**: [core/hmac_auth.py](core/hmac_auth.py), [core/hash_chain.py](core/hash_chain.py)

### 2.3 Authentication — ECDH P-256 + HKDF

The ECDH handshake establishes a shared secret `Z` known only to the two
communicating parties. `K_HMAC` is derived from `Z` via HKDF. Because only
a party that completed the genuine ECDH handshake knows `K_HMAC`, a valid
HMAC tag proves the sender's identity.

A forged HMAC tag (constructed with a random key) is always rejected by
`verify_hmac()`, which uses `hmac.compare_digest()` for constant-time
comparison — eliminating timing-oracle attacks.

**Files**: [core/key_exchange.py](core/key_exchange.py), [core/session_manager.py](core/session_manager.py), [core/hmac_auth.py](core/hmac_auth.py)

### 2.4 Non-Repudiation — RSA-2048 PSS + Blockchain Ledger

**Vehicle-level**: Every METRIC is signed with the vehicle's RSA-2048 private
key before encryption. The controller verifies the signature with the vehicle's
public key (received and stored during KEY_EXCHANGE). Because only the vehicle
holds its private key, a valid signature is cryptographic proof of authorship.

**Controller-level**: The controller RSA-signs every ledger entry hash. An
auditor with the controller's public key can verify any historical entry
independently, without access to the live system. The hash chain (Eq 3.31)
means that modifying any entry also invalidates all subsequent entries.

**Files**: [core/rsa_signatures.py](core/rsa_signatures.py), [core/blockchain_ledger.py](core/blockchain_ledger.py)

### 2.5 Availability — Session Management + Replay Detection

- Sessions expire after 60 seconds (`SESSION_TIMEOUT_SECONDS`). Stale sessions
  are purged to prevent memory exhaustion (slow-burn DoS).
- Sequence numbers increment monotonically per session. The controller rejects
  any message whose sequence number is not strictly greater than the last
  accepted value (replay prevention).
- The 10-second socket timeout (`SOCKET_TIMEOUT`) prevents the controller from
  blocking forever on a crashed vehicle (resource leak prevention).

**File**: [core/session_manager.py](core/session_manager.py)

---

## 3. Algorithm Choices — Why Each Was Selected

### 3.1 AES-256-GCM vs AES-256-CBC

| | AES-GCM | AES-CBC |
|---|---|---|
| **Confidentiality** | Yes (CTR mode) | Yes |
| **Integrity of ciphertext** | Yes (GHASH tag) | No |
| **Padding-oracle resistant** | Yes (no padding) | No (POODLE, BEAST) |
| **Bit-flip resistant** | Yes | No — predictable flip in next block |
| **Associated data (AAD)** | Yes | No |
| **NIST recommendation** | SP 800-38D | Legacy |

AES-GCM is an AEAD (Authenticated Encryption with Associated Data) mode.
It provides confidentiality AND integrity in a single pass, making padding-oracle
and bit-flip attacks impossible. AES-CBC requires a separate MAC, and combining
them incorrectly (MAC-then-Encrypt) enables the Lucky Thirteen attack.

**Choice: AES-256-GCM** — mandatory for any new design; matches TLS 1.3.

### 3.2 ECDH P-256 vs RSA Key Transport

| | ECDH (ephemeral) | RSA Key Transport |
|---|---|---|
| **Forward secrecy** | Yes — d_V, d_C discarded after Z computed | No — past sessions exposed if private key leaks |
| **Key size for 128-bit security** | 32-byte private scalar | 3072-byte RSA modulus |
| **Handshake overhead** | O(1) scalar multiplications | RSA encrypt/decrypt (expensive) |
| **Quantum threat** | Vulnerable (like RSA) | Vulnerable |

ECDH gives **Perfect Forward Secrecy**: even if the controller's long-term key
is compromised years later, an attacker who recorded past ciphertext cannot
decrypt it because the ephemeral private scalars `d_V` and `d_C` no longer
exist. Static RSA key transport has no such property.

P-256 (secp256r1) is chosen because it is standardised by NIST FIPS 186-4,
mandatory in TLS 1.3, and explicitly referenced in the SIGMA-V FYP specification.

**Choice: ECDH P-256 (ephemeral)**

### 3.3 HKDF vs Direct SHA-256

The raw ECDH output `Z` is the x-coordinate of a curve point — not uniformly
random and not safe to use directly as a key.

HKDF (RFC 5869) performs two steps:
1. **Extract**: `PRK = HMAC-SHA256(salt, Z)` — converts Z to a uniform PRK.
2. **Expand**: `K = HMAC-SHA256(PRK, info || counter)` — derives any length,
   with domain separation via the `info` label.

Two HKDF calls with different `info` strings (`sdvn-v1-aes-256-gcm-key` and
`sdvn-v1-hmac-sha256-key`) produce `K_AES` and `K_HMAC` that are
cryptographically independent — a weakness against one cannot expose the other.

**Choice: HKDF-SHA256 with distinct info labels**

### 3.4 RSA-PSS vs RSA-PKCS1v15

| | PSS | PKCS#1 v1.5 |
|---|---|---|
| **Security proof** | Tight, random-oracle model | No tight reduction |
| **Deterministic** | No (random salt per signature) | Yes |
| **Bleichenbacher-style attacks** | Not applicable (signatures only) | Applicable to decryption |
| **NIST / RFC 8017 status** | Recommended | Legacy |

PSS uses a random salt so two signatures of the same message are different —
preventing chosen-message attacks that exploit determinism. PKCS#1 v1.5 has
known theoretical weaknesses and is not recommended for new protocols.

**Choice: RSA-2048 PSS with MAX_LENGTH salt**

### 3.5 HMAC-SHA256 vs Plain SHA-256

A plain `SHA256(payload)` hash provides integrity but NOT authentication — an
attacker who sees `H(m)` can trivially compute `H(tampered_m)` without any key.

HMAC wraps the hash with a secret key:
```
HMAC-SHA256(K, M) = SHA256( (K XOR opad) || SHA256( (K XOR ipad) || M ) )
```

The double-hash construction defends against length-extension attacks. Only a
party knowing `K` can produce or verify a valid tag.

**Choice: HMAC-SHA256 with `K_HMAC` (derived from ECDH)**

### 3.6 Hash Chain vs Simple Sequence Numbers

A simple sequence number detects dropped packets but does NOT detect tampering:
an attacker could change the payload and increment the sequence number without
the receiver noticing.

A SHA-256 hash chain binds each message to its exact payload AND to all prior
messages. Changing any payload changes the chain link at that position and all
subsequent positions. An attacker who drops a message cannot forge the correct
link for the next position without knowing the previous link — which depends on
the (now missing) dropped payload.

**Choice: SHA-256 hash chain (seeded per-session from `K_AES.hex()`)**

---

## 4. Mapping to SIGMA-V FYP Equations

| Equation | Description | Implementation |
|---|---|---|
| **Eq 3.42** | `d_V <- random scalar; Q_V = d_V * G` (vehicle ECDH keypair) | `ECDHKeyExchange.generate_keypair()` in [core/key_exchange.py](core/key_exchange.py) |
| **Eq 3.43** | `d_C <- random scalar; Q_C = d_C * G` (controller ECDH keypair) | `ECDHKeyExchange.generate_keypair()` called in [nodes/controller_node.py:handle_key_exchange()](nodes/controller_node.py) |
| **Eq 3.44** | `Z = d_V * Q_C = d_C * Q_V` (shared secret) | `ECDHKeyExchange.compute_shared_secret()` in [core/key_exchange.py](core/key_exchange.py) |
| **Eq 3.45** | `K_AES = HKDF(Z, salt, info="aes"), K_HMAC = HKDF(Z, salt, info="hmac")` | `ECDHKeyExchange.derive_session_key()` in [core/key_exchange.py](core/key_exchange.py) |
| **Eq 3.31** | `H_i = SHA256(entry_id || vehicle_id || msg_type || SHA256(payload) || ts || H_{i-1})` | `BlockchainLedger._compute_entry_hash()` in [core/blockchain_ledger.py](core/blockchain_ledger.py) |
| **Hash chain (general)** | `H[n] = SHA256(message[n] || H[n-1])` | `HashChain.add()` in [core/hash_chain.py](core/hash_chain.py) |
| **HMAC** | `HMAC-SHA256(K, M) = SHA256((K XOR opad) || SHA256((K XOR ipad) || M))` | `generate_hmac()` in [core/hmac_auth.py](core/hmac_auth.py) |
| **RSA-PSS sign** | `sigma = RSA-PSS-Sign(K_priv, SHA256(data))` | `sign()` in [core/rsa_signatures.py](core/rsa_signatures.py) |
| **RSA-PSS verify** | `valid = RSA-PSS-Verify(K_pub, SHA256(data), sigma)` | `verify_signature()` in [core/rsa_signatures.py](core/rsa_signatures.py) |

---

## 5. Security Architecture Diagram

```
Vehicle Node                                 SDN Controller
────────────────────                         ────────────────────────────────────────
generate d_V, Q_V  (Eq 3.42)
                    ── KEY_EXCHANGE ──>       generate d_C, Q_C  (Eq 3.43)
                                             Z = d_C * Q_V       (Eq 3.44)
                    <── SESSION_ID ──         K_AES, K_HMAC = HKDF(Z) (Eq 3.45)

Z = d_V * Q_C      (Eq 3.44)
K_AES, K_HMAC = HKDF(Z) (Eq 3.45)

For each BEACON:
  hmac_tag = HMAC(K_HMAC, payload)
  ct = AES-GCM(K_AES, payload, AAD)
                    ── BEACON ──────>         ct' = AES-GCM-decrypt(K_AES, ct)
                                             verify HMAC(K_HMAC, ct') == hmac_tag

For each METRIC:
  chain_link = SHA256(payload || prev_link)
  sig = RSA-PSS-Sign(K_V_priv, payload)
  hmac_tag = HMAC(K_HMAC, payload+chain_link)
  ct = AES-GCM(K_AES, {payload,chain_link,sig})
                    ── METRIC ──────>         ct' = AES-GCM-decrypt(K_AES, ct)
                                             verify HMAC(K_HMAC, ...)
                                             verify chain_link matches parallel chain
                                             verify RSA-PSS-Verify(K_V_pub, payload, sig)
                                             ledger.add_entry(sign with K_ctrl_priv)
```

---

## 6. Known Limitations and Production Improvements

### 6.1 Quantum Resistance — Kyber PQC

All algorithms used (AES-256-GCM, ECDH P-256, RSA-2048, HMAC-SHA256) are
vulnerable to Grover's algorithm (symmetric keys) and Shor's algorithm
(asymmetric keys) on a sufficiently powerful quantum computer.

**Production fix**: Replace ECDH P-256 with **CRYSTALS-Kyber** (NIST PQC
standard, FIPS 203) for key encapsulation, and RSA-2048 signatures with
**CRYSTALS-Dilithium** (FIPS 204) or **SPHINCS+** (FIPS 205). The `cryptography`
library does not yet expose these natively; they would require liboqs bindings.

AES-256 and HMAC-SHA256 are considered quantum-safe (Grover only halves
effective key length, leaving 128 bits of security for AES-256).

### 6.2 Distributed Ledger — Hyperledger Fabric

The `BlockchainLedger` in this project is a **local, single-node** append-only
log. It has no consensus mechanism, no peer replication, and no Byzantine
fault tolerance. A compromised controller can truncate or replace the entire
ledger file.

**Production fix**: Replace with **Hyperledger Fabric** or a similar permissioned
blockchain. Each ledger write would be endorsed by multiple peer controllers,
and the consensus protocol (Raft or PBFT) would prevent any single node from
unilaterally altering the record. The SIGMA-V FYP discusses this architecture.

### 6.3 Threshold Signatures

Currently a single controller RSA key signs all ledger entries. If that key
is compromised, an attacker can forge arbitrary ledger entries retroactively.

**Production fix**: Use **threshold RSA or BLS signatures** where M of N
controllers must co-sign each entry. No single key compromise breaks the
non-repudiation guarantee.

### 6.4 Certificate-Based Authentication

Vehicle identity is currently established only by the ECDH session — there is
no PKI binding the vehicle's RSA key to a verified identity (e.g. VIN number).
A rogue node can complete a valid handshake and claim any `vehicle_id`.

**Production fix**: Issue X.509 certificates signed by a trusted CA during
vehicle registration. The KEY_EXCHANGE message would include the certificate,
and the controller would validate the certificate chain before accepting the
session.

### 6.5 Session ID and HKDF Salt

The HKDF salt is fixed (`sdvn-demo-2025-ecdh-salt`) for demo reproducibility.
A fixed salt means that two sessions with the same ECDH shared secret produce
the same `K_AES` and `K_HMAC` — a pre-computation risk.

**Production fix**: Generate a fresh random 256-bit salt per session (exchanged
as part of the KEY_EXCHANGE message) so key material is session-unique even
if the ECDH secret is somehow reused.

### 6.6 Key Storage

RSA keypairs are generated in memory on every run and are never persisted.
Restarting the controller means old ledger signatures can no longer be verified.

**Production fix**: Store long-term keys in a **Hardware Security Module (HSM)**
or encrypted key vault (HashiCorp Vault, AWS KMS). Load them at runtime via
environment variables or a secrets management API — never hard-code.

### 6.7 Replay Window

The replay detection window (`REPLAY_WINDOW_SECONDS = 30.0`) assumes both
parties have synchronised clocks. In a vehicular network, GPS-disciplined
clocks may have drift of ±1–2 seconds; a 30-second window is a reasonable
conservative choice but could be tightened with NTP or PTP clock discipline.

---

## 7. Full Message Security Stack

| Layer | BEACON | METRIC |
|---|---|---|
| 1 (innermost) | Plaintext payload | Plaintext payload |
| 2 | HMAC-SHA256(K_HMAC, payload) | Hash chain: H[i] = SHA256(payload || H[i-1]) |
| 3 | — | RSA-PSS-Sign(K_V_priv, payload) |
| 4 | HMAC-SHA256(K_HMAC, payload) | HMAC-SHA256(K_HMAC, payload + chain_link) |
| 5 (outermost) | AES-256-GCM(K_AES, payload, AAD) | AES-256-GCM(K_AES, {payload,chain,sig}, AAD) |

The AAD (Additional Authenticated Data) for both message types includes the
`msg_type` and `session_id`, binding the encrypted payload to its intended
context. Replacing the header while keeping the ciphertext is detected by the
GCM authentication tag.

---

## 8. Summary Table

| Security Property | Primary Mechanism | Secondary Mechanism | Module |
|---|---|---|---|
| Confidentiality | AES-256-GCM encryption | ECDH-derived K_AES | `aes_gcm_encrypt.py`, `key_exchange.py` |
| Integrity (message) | HMAC-SHA256 with K_HMAC | AES-GCM auth tag | `hmac_auth.py` |
| Integrity (sequence) | SHA-256 hash chain | Parallel controller chain | `hash_chain.py` |
| Authentication | ECDH-derived K_HMAC | HMAC constant-time verify | `key_exchange.py`, `hmac_auth.py` |
| Non-Repudiation (vehicle) | RSA-2048 PSS signature | Blockchain ledger entry | `rsa_signatures.py` |
| Non-Repudiation (controller) | Controller RSA-signs ledger entries | Hash chain links | `blockchain_ledger.py` |
| Availability | 60-second session timeout | Socket timeout, purge_expired | `session_manager.py` |
