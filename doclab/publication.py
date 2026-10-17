"""Final application response-start checkpoint; never holds locks across send()."""
from anyio import to_thread
from starlette.responses import JSONResponse
from .models import Document
from .security import SessionInvalidatedError


class PublicationGuard:
    def __init__(self, app, sessions, documents, document_lock, policy):
        self.app = app
        self.sessions = sessions
        self.documents = documents
        self.document_lock = document_lock
        self.policy = policy

    def check(self, scope):
        state = scope.get("state", {})
        ticket = state.get("session_ticket")
        proof = state.get("publication_docs")
        if ticket is None:
            return 401, "publication_session_invalidated", "Authentication required"
        if proof is None:
            return 500, "publication_proof_missing", "Internal server error"
        try:
            # Same order as all endpoint critical sections; no lock across async I/O.
            with self.sessions.checkpoint(ticket) as lease, self.document_lock:
                principal = lease.check()
                current = self.documents()
                for resource_id, version, action in proof:
                    raw = current.get(resource_id)
                    doc = Document.model_validate(raw) if raw is not None else None
                    if doc is None or doc.version != version or not self.policy(principal, doc, action).allowed:
                        return 409, "publication_snapshot_changed", "Document changed; retry"
                lease.check()  # Time can advance even while revocation is locked out.
        except SessionInvalidatedError:
            return 401, "publication_session_invalidated", "Authentication required"
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/v1/"):
            return await self.app(scope, receive, send)
        replaced = False

        async def checked_send(message):
            nonlocal replaced
            if replaced:
                return  # Discard the original successful body and any trailers.
            if message["type"] == "http.response.start" and 200 <= message["status"] < 300:
                failure = await to_thread.run_sync(self.check, scope)
                if failure is not None:
                    status, reason, detail = failure
                    scope.setdefault("state", {}).get("context", {})["reason"] = reason
                    headers = {"WWW-Authenticate":"Bearer"} if status == 401 else {}
                    headers["Cache-Control"] = "no-store"
                    replaced = True
                    await JSONResponse({"detail":detail}, status_code=status, headers=headers)(scope, receive, send)
                    return
            await send(message)

        await self.app(scope, receive, checked_send)
