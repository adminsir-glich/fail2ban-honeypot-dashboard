"""
watcher.py — Watch cowrie.json and auth.log with watchdog and broadcast new events over an asyncio.Queue.
Subscribers receive each new event as a parsed dict.
"""
import asyncio
import json
import re
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class CowrieTailer:
    """Tails a JSONL log file and broadcasts new lines to subscribers."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._subscribers: list[asyncio.Queue] = []
        self._last_pos = 0
        self._loop: asyncio.AbstractEventLoop | None = None

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def broadcast(self, event: dict):
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest, push newest — better than blocking
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass

    def start(self, loop: asyncio.AbstractEventLoop):
        """Start the watchdog observer (call from async code with running loop)."""
        self._loop = loop
        # Seed position to end-of-file so we don't replay old events on startup
        if self.path.exists():
            self._last_pos = self.path.stat().st_size

        handler = _Handler(self)
        observer = Observer()
        observer.schedule(handler, str(self.path.parent), recursive=False)
        observer.daemon = True
        observer.start()
        return observer

    def _on_change(self):
        """Called from watchdog thread when the log file changes."""
        if not self.path.exists():
            return
        try:
            size = self.path.stat().st_size
            if size < self._last_pos:
                # File rotated/truncated — restart from beginning
                self._last_pos = 0
            with self.path.open("r", errors="replace") as f:
                f.seek(self._last_pos)
                new = f.read()
                self._last_pos = f.tell()
            for line in new.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Schedule broadcast on the asyncio loop (we're in a watchdog thread)
                if self._loop is not None:
                    asyncio.run_coroutine_threadsafe(self.broadcast(event), self._loop)
        except Exception as e:
            print(f"[watcher] error: {e}")


class _Handler(FileSystemEventHandler):
    def __init__(self, tailer: CowrieTailer):
        self.tailer = tailer

    def on_modified(self, event):
        if not event.is_directory and Path(event.src_path).name == self.tailer.path.name:
            self.tailer._on_change()

    def on_created(self, event):
        if not event.is_directory and Path(event.src_path).name == self.tailer.path.name:
            self.tailer._on_change()


class AuthLogTailer:
    """Tails /var/log/auth.log and broadcasts SSH failures ONLY (ignores successes for security)."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._subscribers: list[asyncio.Queue] = []
        self._last_pos = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        
        # Regexes for SSH failures (no success regexes to avoid security leak of admin logins)
        self.fail_invalid_re = re.compile(r"sshd\[(\d+)\]: Failed password for invalid user (\S+) from (\S+) port \d+")
        self.fail_re = re.compile(r"sshd\[(\d+)\]: Failed password for (\S+) from (\S+) port \d+")

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def broadcast(self, event: dict):
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass

    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        if self.path.exists():
            self._last_pos = self.path.stat().st_size

        handler = _AuthHandler(self)
        observer = Observer()
        observer.schedule(handler, str(self.path.parent), recursive=False)
        observer.daemon = True
        observer.start()
        return observer

    def _on_change(self):
        if not self.path.exists():
            return
        try:
            size = self.path.stat().st_size
            if size < self._last_pos:
                self._last_pos = 0
            with self.path.open("r", errors="replace") as f:
                f.seek(self._last_pos)
                new = f.read()
                self._last_pos = f.tell()
            for line in new.splitlines():
                line = line.strip()
                if not line:
                    continue
                
                event = self._parse_line(line)
                if event and self._loop is not None:
                    asyncio.run_coroutine_threadsafe(self.broadcast(event), self._loop)
        except Exception as e:
            print(f"[auth watcher] error: {e}")

    def _parse_line(self, line: str) -> dict | None:
        ts_match = re.match(r"^(\S+)", line)
        if not ts_match:
            return None
        timestamp = ts_match.group(1)
        if len(timestamp) > 19:
            timestamp = timestamp[:19] + "Z"

        # Check Failed password for invalid user
        m = self.fail_invalid_re.search(line)
        if m:
            pid, user, ip = m.group(1), m.group(2), m.group(3)
            return {
                "eventid": "cowrie.login.failed",
                "src_ip": ip,
                "username": user,
                "password": "[not logged]",
                "timestamp": timestamp,
                "session": f"real-ssh-{pid}",
                "is_real_ssh": True
            }

        # Check Failed password
        m = self.fail_re.search(line)
        if m:
            pid, user, ip = m.group(1), m.group(2), m.group(3)
            return {
                "eventid": "cowrie.login.failed",
                "src_ip": ip,
                "username": user,
                "password": "[not logged]",
                "timestamp": timestamp,
                "session": f"real-ssh-{pid}",
                "is_real_ssh": True
            }
        return None


class _AuthHandler(FileSystemEventHandler):
    def __init__(self, tailer: AuthLogTailer):
        self.tailer = tailer

    def on_modified(self, event):
        if not event.is_directory and Path(event.src_path).name == self.tailer.path.name:
            self.tailer._on_change()

    def on_created(self, event):
        if not event.is_directory and Path(event.src_path).name == self.tailer.path.name:
            self.tailer._on_change()
