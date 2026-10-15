"""Opaque, ephemeral local sessions; authorization is independent of token format."""
from dataclasses import dataclass
import hashlib
import re
import secrets
import threading
import time
from .models import Document, Principal


class Sessions:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._items = {}
        self._lock = threading.Lock()

    def issue(self, principal: Principal, ttl=900):
        if not isinstance(principal, Principal) or type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("validated principal and 1..3600 second TTL required")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._lock:
            self._items[digest] = (principal, self.clock() + ttl)
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
        if not isinstance(token, str):
            return
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            self._items.pop(digest, None)


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
