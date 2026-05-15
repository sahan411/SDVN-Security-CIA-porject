"""
vehicle_node.py — Vehicle Node: the initiating party in the secure channel.

Responsibilities:
  1. Broadcast a BEACON so the controller knows this vehicle is active.
  2. Perform the ECDH KEY_EXCHANGE to establish a forward-secret session key.
  3. Send AES-GCM encrypted, RSA-signed METRIC messages to the controller.
  4. Optionally submit LEDGER_UPDATE requests for security-relevant events.
"""

# TODO: Implement VehicleNode class using core modules.
# Suggested structure:
#
#   class VehicleNode:
#       def __init__(self, node_id: str): ...
#       def broadcast_beacon(self, sock): ...
#       def perform_key_exchange(self, sock) -> Session: ...
#       def send_metric(self, sock, session, payload: dict): ...
