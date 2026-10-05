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


# read as well as append, to inspect the tail; without O_BINARY the Windows C runtime turns the record's "\n" into
# "\r\n"; it does not exist elsewhere
OPEN_FLAGS = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)


class AuditError(RuntimeError):
    pass


def _line(record: dict) -> bytes:
    return (json.dumps({"ts": round(time.time(), 3), **record}, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


TAIL = 65536  # bytes of the file read back to judge its last line; a record is far smaller


def _tail_repair(fd: int) -> bytes:
    """What the next record must be preceded by: nothing when the file is empty or its last line is a complete record
    ending in a newline, otherwise an audit_repaired record (on a line of its own), so the partial line a writer that
    died mid-record left behind stays a line of its own instead of becoming the head of the next record. The last
    line is parsed, not just its last byte: a writer that died right after the repair's own newline leaves a torn line
    that does end in one. A last line longer than TAIL is not judged, and gets the repair."""
    size = os.fstat(fd).st_size
    if size == 0:
        return b""
    os.lseek(fd, max(size - TAIL, 0), os.SEEK_SET)
    tail = os.read(fd, TAIL)
    last = tail.rstrip(b"\n").rsplit(b"\n", 1)[-1]
    if tail.endswith(b"\n") and (size <= TAIL or b"\n" in tail[:-1]) and _is_record(last):
        return b""
    return (b"" if tail.endswith(b"\n") else b"\n") + _line({"event": "audit_repaired"})


def _is_record(line: bytes) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = _line(record)
        try:
            with self._lock:
                fd = os.open(self.path, OPEN_FLAGS, 0o600)
                try:
                    # an exclusive lock on the file, held through write and fsync, so separate AuditLog instances and
                    # separate processes can never interleave the bytes of two records
                    _lock(fd)
                    try:
                        data = memoryview(_tail_repair(fd) + line)
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
