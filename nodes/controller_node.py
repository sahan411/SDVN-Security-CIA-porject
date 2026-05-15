"""
controller_node.py — SDN Controller: the receiving party in the secure channel.

Responsibilities:
  1. Listen for BEACON messages and maintain a topology map of active vehicles.
  2. Complete the ECDH KEY_EXCHANGE to derive a shared session key.
  3. Receive, decrypt, and verify METRIC messages.
  4. Append every significant event to the BlockchainLedger.
  5. Detect and log replay / flood attacks via the attack_simulator hooks.
"""

# TODO: Implement ControllerNode class using core modules.
# Suggested structure:
#
#   class ControllerNode:
#       def __init__(self): ...
#       def listen(self): ...          # socket.bind + accept loop
#       def handle_beacon(self, msg: SecureMessage): ...
#       def handle_key_exchange(self, msg: SecureMessage) -> Session: ...
#       def handle_metric(self, msg: SecureMessage, session: Session): ...
