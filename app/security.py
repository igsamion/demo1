import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from itsdangerous import BadSignature, Signer


@dataclass
class SessionData:
    session_id: str
    user: dict[str, Any]
    created_at: float
    last_activity: float
    csrf_token: str
    chat_history: list[dict[str, str]] = field(default_factory=list)


class SessionStore:
    def __init__(self, secret: str) -> None:
        self._signer = Signer(secret)
        self._store: dict[str, SessionData] = {}

    def create(self, user: dict[str, Any]) -> SessionData:
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        data = SessionData(
            session_id=session_id,
            user=user,
            created_at=now,
            last_activity=now,
            csrf_token=secrets.token_urlsafe(32),
        )
        self._store[session_id] = data
        return data

    def rotate(self, session_id: str, user: dict[str, Any]) -> SessionData:
        self.delete(session_id)
        return self.create(user)

    def delete(self, session_id: str) -> None:
        self._store.pop(session_id, None)

    def get(self, session_id: str) -> SessionData | None:
        return self._store.get(session_id)

    def sign(self, session_id: str) -> str:
        return self._signer.sign(session_id.encode()).decode()

    def unsign(self, signed: str) -> str | None:
        try:
            raw = self._signer.unsign(signed.encode()).decode()
        except BadSignature:
            return None
        return raw


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self.window = 60
        self.events: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        history = [t for t in self.events.get(key, []) if now - t < self.window]
        if len(history) >= self.limit:
            self.events[key] = history
            return False
        history.append(now)
        self.events[key] = history
        return True


class LockoutManager:
    def __init__(self, threshold: int, window_min: int, duration_min: int) -> None:
        self.threshold = threshold
        self.window = window_min * 60
        self.duration = duration_min * 60
        self.failures: dict[str, list[float]] = {}
        self.locked_until: dict[str, float] = {}

    def is_locked(self, key: str) -> bool:
        until = self.locked_until.get(key)
        if until is None:
            return False
        if time.time() > until:
            self.locked_until.pop(key, None)
            return False
        return True

    def record_failure(self, key: str) -> None:
        now = time.time()
        history = [t for t in self.failures.get(key, []) if now - t < self.window]
        history.append(now)
        self.failures[key] = history
        if len(history) >= self.threshold:
            self.locked_until[key] = now + self.duration

    def reset(self, key: str) -> None:
        self.failures.pop(key, None)
        self.locked_until.pop(key, None)


class SprayDetector:
    def __init__(self, window_min: int = 10, threshold: int = 10) -> None:
        self.window = window_min * 60
        self.threshold = threshold
        self.events: dict[str, list[tuple[float, str]]] = {}

    def register(self, ip: str, username: str) -> bool:
        now = time.time()
        history = [
            (ts, user)
            for ts, user in self.events.get(ip, [])
            if now - ts < self.window
        ]
        history.append((now, username))
        self.events[ip] = history
        unique_users = {user for _, user in history}
        return len(unique_users) >= self.threshold


def constant_time_compare(val1: str, val2: str) -> bool:
    return hmac.compare_digest(val1.encode(), val2.encode())
