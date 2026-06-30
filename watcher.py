"""
watcher.py — Watch cowrie.json and auth.log using asyncio polling.
Subscribers receive each new event as a parsed dict.
"""
import asyncio
import json
import re
from pathlib import Path

class CowrieTailer:
    """Tails a JSONL log file using polling and broadcasts new lines to subscribers."""

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
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass

    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        if self.path.exists():
            self._last_pos = self.path.stat().st_size
        
        # Start the polling loop task
        asyncio.create_task(self._poll_loop())

    async def _poll_loop(self):
        while True:
            try:
                await asyncio.sleep(0.8) # check every 800ms
                if not self.path.exists():
                    continue
                size = self.path.stat().st_size
                if size < self._last_pos:
                    self._last_pos = 0
                if size > self._last_pos:
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
                            await self.broadcast(event)
                        except Exception:
                            continue
            except Exception as e:
                print(f"[watcher] poll error: {e}")


class AuthLogTailer:
    """Tails /var/log/auth.log using polling and broadcasts SSH failures ONLY."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._subscribers: list[asyncio.Queue] = []
        self._last_pos = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        
        # Regexes for SSH failures
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
        
        # Start the polling loop task
        asyncio.create_task(self._poll_loop())

    async def _poll_loop(self):
        while True:
            try:
                await asyncio.sleep(1.0) # check every 1s
                if not self.path.exists():
                    continue
                size = self.path.stat().st_size
                if size < self._last_pos:
                    self._last_pos = 0
                if size > self._last_pos:
                    with self.path.open("r", errors="replace") as f:
                        f.seek(self._last_pos)
                        new = f.read()
                        self._last_pos = f.tell()
                    for line in new.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        
                        event = self._parse_line(line)
                        if event:
                            await self.broadcast(event)
            except Exception as e:
                print(f"[auth watcher] poll error: {e}")

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
