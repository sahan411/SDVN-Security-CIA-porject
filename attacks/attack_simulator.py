"""
attack_simulator.py — Simulates and detects three attack classes.

Demonstrates the Availability property: the system remains operational and
correct even under active adversarial conditions.

Attack classes modelled:
  1. Replay attack    — retransmit a previously captured legitimate packet.
  2. MITM tampering   — flip a byte in the ciphertext to simulate modification.
  3. Flood attack     — send a burst of malformed packets to exhaust resources.

Each attack is paired with a detection check that shows exactly why it fails
against the security controls implemented in the core modules.
"""

# TODO: Implement AttackSimulator class.
# Suggested structure:
#
#   class AttackSimulator:
#       def replay_attack(self, captured_msg: SecureMessage, session: Session) -> bool:
#           """Returns True if the replay is incorrectly accepted (test failure)."""
#
#       def mitm_tamper(self, msg: SecureMessage) -> SecureMessage:
#           """Returns a bit-flipped copy of msg."""
#
#       def flood_attack(self, target_host: str, target_port: int, count: int = 1000):
#           """Sends *count* malformed UDP datagrams at the target."""
