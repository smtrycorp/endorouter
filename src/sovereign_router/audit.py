"""Append-only JSONL audit log. A record is written and flushed to disk BEFORE anything is sent upstream; if it cannot
be written, the request is refused. Records never contain prompt or completion content."""

from __future__ import annotations

import json
import os
import threading
import time


class AuditError(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = json.dumps({"ts": round(time.time(), 3), **record}, separators=(",", ":"), sort_keys=True) + "\n"
        try:
            with self._lock:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    data = memoryview(line.encode("utf-8"))
                    while data:  # a short write is not a record: keep writing until every byte is accepted
                        n = os.write(fd, data)
                        if n <= 0:
                            raise OSError("audit write made no progress")
                        data = data[n:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as e:
            raise AuditError(f"audit log unavailable ({e}); refusing to dispatch") from e
