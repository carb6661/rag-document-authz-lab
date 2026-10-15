"""Hardened object API; unsafe switch is only used in local in-process comparisons."""
from collections import deque
from copy import deepcopy
import json
from pathlib import Path
import threading
from typing import Annotated
import uuid

from fastapi import Depends, FastAPI, HTTPException, Path as APIPath, Request
from fastapi.exceptions import RequestValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from .models import Document, DocumentPatch, Principal
from .security import Sessions, decide

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 65_536


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        if scope["method"] == "PATCH" and headers.get(b"content-type", b"").split(b";")[0].strip().lower() != b"application/json":
            return await JSONResponse({"detail":"JSON required"}, status_code=415)(scope, receive, send)
        messages, size = [], 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            size += len(msg.get("body", b""))
            if size > MAX_BODY:
                return await JSONResponse({"detail":"Body too large"}, status_code=413)(scope, receive, send)
            messages.append(msg)
            if not msg.get("more_body", False):
                break
        async def replay():
            if messages:
                return messages.pop(0)
            return {"type":"http.request","body":b"","more_body":False}
        await self.app(scope, replay, send)


def create_app(*, unsafe=False, sessions=None):
    app = FastAPI(title="RAG Document Authorization Lab", version="0.1.0")
    app.state.sessions = sessions or Sessions()
    raw = json.loads((ROOT / "fixtures/documents.json").read_text(encoding="utf-8"))
    parsed = [Document.model_validate(item) for item in raw]
    if len({d.id for d in parsed}) != len(parsed):
        raise ValueError("duplicate fixture id")
    app.state.documents = {d.id:d.model_dump() for d in parsed}
    app.state.lock = threading.Lock()
    app.state.audit = deque(maxlen=256)
    app.state.audit_lock = threading.Lock()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1","localhost","testserver"])
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def audit(request, call_next):
        request.state.context = {"actor":None, "tenant":None, "role":None,
                                 "action":request.method, "resource":None,
                                 "reason":"request_rejected"}
        request_id = uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        if request.url.path.startswith("/v1/"):
            record = {"request_id":request_id, **request.state.context,
                      "status":response.status_code, "allowed":200 <= response.status_code < 300}
            with app.state.audit_lock:
                app.state.audit.append(record)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail":"Invalid request schema"}, status_code=422)

    def identity(request: Request):
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        principal = app.state.sessions.resolve(token) if scheme.lower() == "bearer" else None
        if principal is None:
            request.state.context["reason"] = "unauthenticated"
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate":"Bearer"})
        request.state.context.update(actor=principal.user_id, tenant=principal.tenant_id, role=principal.role)
        return principal

    def authorize(request, principal, raw_doc, action):
        doc = Document.model_validate(raw_doc) if raw_doc is not None else None
        decision = decide(principal, doc, action, unsafe=unsafe)
        request.state.context.update(action=action, reason=decision.reason)
        if not decision.allowed:
            if decision.reason == "read_only_role" or (unsafe and doc is not None):
                raise HTTPException(403, "Action not permitted")
            raise HTTPException(404, "Document not found")

    @app.get("/health")
    def health():
        return {"status":"ok", "mode":"unsafe-in-process" if unsafe else "hardened"}

    @app.get("/v1/documents")
    def list_documents(request: Request, principal: Annotated[Principal, Depends(identity)]):
        request.state.context.update(action="list", reason="unsafe_list_unfiltered" if unsafe else "tenant_owner_filter")
        with app.state.lock:
            return {"documents":[deepcopy(raw_doc) for raw_doc in app.state.documents.values()
                                 if decide(principal, Document.model_validate(raw_doc), "read", unsafe=unsafe).allowed]}

    ResourceID = Annotated[str, APIPath(pattern=r"^[a-z0-9-]{1,64}$")]

    @app.get("/v1/documents/{resource_id}", response_model=Document)
    def read_document(resource_id: ResourceID, request: Request,
                      principal: Annotated[Principal, Depends(identity)]):
        request.state.context["resource"] = resource_id
        with app.state.lock:
            raw_doc = app.state.documents.get(resource_id)
            authorize(request, principal, raw_doc, "read")
            return deepcopy(raw_doc)

    @app.patch("/v1/documents/{resource_id}", response_model=Document)
    def patch_document(resource_id: ResourceID, patch: DocumentPatch, request: Request,
                       principal: Annotated[Principal, Depends(identity)]):
        request.state.context["resource"] = resource_id
        changes = patch.model_dump(exclude_none=True, exclude={"expected_version"})
        if not changes:
            raise HTTPException(422, "No editable fields")
        with app.state.lock:
            raw_doc = app.state.documents.get(resource_id)
            authorize(request, principal, raw_doc, "write")
            if patch.expected_version != raw_doc["version"]:
                request.state.context["reason"] = "version_conflict"
                raise HTTPException(409, "Version conflict")
            updated = {**raw_doc, **changes, "version":raw_doc["version"]+1}
            app.state.documents[resource_id] = Document.model_validate(updated).model_dump()
            return deepcopy(updated)

    return app


def demo_tokens(app):
    """Local trusted issuer. No HTTP issuance route or user-selectable claims."""
    raw = json.loads((ROOT / "fixtures/principals.json").read_text(encoding="utf-8"))
    return {name:app.state.sessions.issue(Principal.model_validate(value)) for name,value in raw.items()}
