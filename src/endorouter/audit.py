"""Append-only JSONL audit log. A record is written and flushed to disk BEFORE anything is sent upstream; if it cannot
be written, the request is refused. Records never contain prompt or completion content."""

from __future__ import annotations

import json
import os
import sys
import threading
import time

if sys.platform == "win32":
    import msvcrt

    def _lock(fd: int) -> None:
        # Windows locks a byte range, not the file, so every writer locks the same first byte (which need not exist
        # yet). LK_LOCK would retry once a second, a long wait for a lock held for microseconds: poll instead.
        os.lseek(fd, 0, os.SEEK_SET)
        deadline = time.monotonic() + 10
        while True:
            try:
                return msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.001)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


# without O_BINARY the Windows C runtime turns the record's "\n" into "\r\n"; it does not exist elsewhere
OPEN_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)


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
                fd = os.open(self.path, OPEN_FLAGS, 0o600)
                try:
                    # an exclusive lock on the file, held through write and fsync, so separate AuditLog instances and
                    # separate processes can never interleave the bytes of two records
                    _lock(fd)
                    try:
                        data = memoryview(line.encode("utf-8"))
                        while data:  # a short write is not a record: keep writing until every byte is accepted
                            n = os.write(fd, data)
                            if n <= 0:
                                raise OSError("audit write made no progress")
                            data = data[n:]
                        os.fsync(fd)
                    finally:
                        _unlock(fd)
                finally:
                    os.close(fd)
        except OSError as e:
            raise AuditError(f"audit log unavailable ({e}); refusing to dispatch") from e
