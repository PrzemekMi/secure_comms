from typing import Callable

NodeId = str
RawPayload = bytes
# Callback signature: fn(from_node_id: NodeId, payload: RawPayload) -> None
SubscriberCallback = Callable[[NodeId, RawPayload], None]
