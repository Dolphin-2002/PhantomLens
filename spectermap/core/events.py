import asyncio
from collections import deque
from datetime import UTC, datetime


class EventBus:
    def __init__(self):
        self.history = deque(maxlen=300)
        self.listeners = set()

    def emit(self, message, scan_id=None, level="info"):
        item = {
            "time": datetime.now(UTC).isoformat(),
            "message": message,
            "scan_id": scan_id,
            "level": level,
        }
        self.history.append(item)
        for queue in tuple(self.listeners):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(item)

    def subscribe(self):
        queue = asyncio.Queue(maxsize=300)
        self.listeners.add(queue)
        return queue


bus = EventBus()
