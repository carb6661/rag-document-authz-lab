"""Opaque, ephemeral local sessions; authorization is independent of token format."""
from dataclasses import dataclass
import hashlib
import re
import secrets
import threading
import time
from .models import Document, Principal


class SessionCapacityError(RuntimeError):
    pass


class Sessions:
    def __init__(self, clock=time.monotonic, max_sessions=1024):
        if type(max_sessions) is not int or max_sessions < 1:
            raise ValueError("positive session capacity required")
        self.clock = clock
        self.max_sessions = max_sessions
        self._items = {}
        self._lock = threading.Lock()

    def _purge(self, now):
        expired = [key for key, item in self._items.items() if item[1] <= now]
        for key in expired:
            del self._items[key]
        return len(expired)

    def purge_expired(self):
        with self._lock:
            return self._purge(self.clock())

    def issue(self, principal: Principal, ttl=900):
        if not isinstance(principal, Principal) or type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("validated principal and 1..3600 second TTL required")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._lock:
            now = self.clock()
            self._purge(now)
            if len(self._items) >= self.max_sessions:
                raise SessionCapacityError("active session capacity reached")
            self._items[digest] = (principal, now + ttl)
        return token

    def resolve(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._lock:
            item = self._items.get(digest)
            if item is None:
                return None
            if item[1] <= self.clock():
                self._items.pop(digest, None)
                return None
            return item[0]

    def revoke(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            self._items.pop(digest, None)

    def revoke_subject(self, tenant_id, user_id):
        """Trusted local operation: revoke one tenant member's current sessions."""
        if any(not isinstance(value, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", value)
               for value in (tenant_id, user_id)):
            raise ValueError("validated tenant/user identifiers required")
        with self._lock:
            self._purge(self.clock())
            matched = [key for key, item in self._items.items()
                       if (item[0].tenant_id, item[0].user_id) == (tenant_id, user_id)]
            for key in matched:
                del self._items[key]
            return len(matched)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def decide(principal: Principal, doc: Document | None, action: str, *, unsafe=False):
    if action not in ("read", "write"):
        return Decision(False, "unknown_action")
    if doc is None:
        return Decision(False, "not_found")
    if unsafe:
        # Intentionally flawed ONLY for the in-process synthetic experiment.
        return Decision(action == "read" or principal.role != "reader", "unsafe_object_scope_omitted")
    if principal.tenant_id != doc.tenant_id:
        return Decision(False, "tenant_mismatch")
    if principal.role != "tenant_admin" and principal.user_id != doc.owner_id:
        return Decision(False, "owner_mismatch")
    if action == "write" and principal.role == "reader":
        return Decision(False, "read_only_role")
    return Decision(True, "tenant_and_object_policy")
