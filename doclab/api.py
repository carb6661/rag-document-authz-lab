"""Hardened object API; unsafe switch is only used in local in-process comparisons."""
from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
import asyncio
import json
from pathlib import Path
import threading
from typing import Annotated
import uuid

from fastapi import Depends, FastAPI, HTTPException, Path as APIPath, Request
from fastapi.exceptions import RequestValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from .models import Document, DocumentPatch, Principal, RetrievalRequest
from .ingress import BodyLimit, MAX_BODY
from .retrieval import rank_authorized
from .security import Sessions, SessionInvalidatedError, decide
from .publication import PublicationGuard

ROOT = Path(__file__).resolve().parents[1]


def create_app(*, unsafe=False, sessions=None):
    app = FastAPI(title="RAG Document Authorization Lab", version="0.3.0")
    app.state.sessions = sessions or Sessions()
    raw = json.loads((ROOT / "fixtures/documents.json").read_text(encoding="utf-8"))
    parsed = [Document.model_validate(item) for item in raw]
    if len({d.id for d in parsed}) != len(parsed):
        raise ValueError("duplicate fixture id")
    app.state.documents = {d.id:d.model_dump() for d in parsed}
    app.state.lock = threading.Lock()
    app.state.audit = deque(maxlen=256)
    app.state.audit_lock = threading.Lock()
    app.state.audit_meta = {"sequence":0, "dropped":0}
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1","localhost","testserver"])
    app.add_middleware(BodyLimit)
    app.add_middleware(PublicationGuard, sessions=app.state.sessions,
        documents=lambda:app.state.documents, document_lock=app.state.lock,
        policy=lambda principal, doc, action:decide(principal,doc,action,unsafe=unsafe))

    @app.middleware("http")
    async def audit(request, call_next):
        request.state.context = {"actor":None, "tenant":None, "role":None,
                                 "action":request.method, "resource":None,
                                 "reason":"request_rejected", "mutation_committed":False}
        request_id = uuid.uuid4().hex

        def record(status):
            if not request.url.path.startswith("/v1/"):
                return
            event = {"request_id":request_id, **request.state.context, "status":status,
                     "allowed":200 <= status < 300,
                     "timestamp":datetime.now(timezone.utc).isoformat()}
            event["reason"] = request.scope.get("gate_reason", event["reason"])
            with app.state.audit_lock:
                app.state.audit_meta["sequence"] += 1
                if len(app.state.audit) == app.state.audit.maxlen:
                    app.state.audit_meta["dropped"] += 1
                event["sequence"] = app.state.audit_meta["sequence"]
                app.state.audit.append(event)

        try:
            response = await call_next(request)
        except asyncio.CancelledError:
            request.state.context["reason"] = "request_cancelled"
            record(499)  # Internal audit marker, not a promised wire response.
            raise
        except Exception:
            request.state.context["reason"] = "internal_error"
            response = JSONResponse({"detail":"Internal server error"}, status_code=500)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        record(response.status_code)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail":"Invalid request schema"}, status_code=422)

    @app.exception_handler(SessionInvalidatedError)
    async def invalid_session(request, exc):
        request.state.context["reason"] = "checkpoint_session_invalidated"
        return JSONResponse({"detail":"Authentication required"},status_code=401,
                            headers={"WWW-Authenticate":"Bearer"})

    def remember(request, rows, action):
        request.state.publication_docs = tuple((row["id"],row["version"],action) for row in rows)

    def identity(request: Request):
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        ticket = app.state.sessions.authenticate(token) if scheme.lower() == "bearer" else None
        if ticket is None:
            request.state.context["reason"] = "unauthenticated"
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate":"Bearer"})
        request.state.session_ticket = ticket
        principal = ticket.principal
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
        with app.state.sessions.checkpoint(request.state.session_ticket), app.state.lock:
            rows = [deepcopy(raw_doc) for raw_doc in app.state.documents.values()
                    if decide(principal, Document.model_validate(raw_doc), "read", unsafe=unsafe).allowed]
            remember(request, rows, "read")
            return {"documents":rows}

    @app.post("/v1/retrieve")
    def retrieve(query: RetrievalRequest, request: Request,
                 principal: Annotated[Principal, Depends(identity)]):
        request.state.context.update(action="retrieve",
            reason="unsafe_retrieval_unfiltered" if unsafe else "authorization_before_scoring")
        # Authorize and snapshot consistently; never send rejected documents to the scorer.
        with app.state.sessions.checkpoint(request.state.session_ticket), app.state.lock:
            snapshots = [deepcopy(raw_doc) for raw_doc in app.state.documents.values()
                         if decide(principal, Document.model_validate(raw_doc), "read", unsafe=unsafe).allowed]
            remember(request, snapshots, "read")
        terms = tuple(dict.fromkeys(query.query.casefold().split()))
        hits = rank_authorized(snapshots, terms, query.top_k)
        return {"retrieval":"exact-keyword", "hits":hits,
                "limitations":["Not semantic retrieval or an LLM answer.",
                               "Citations identify a synthetic document version.",
                               "Session, access and versions are rechecked before response start; later changes cannot recall sent data."]}

    ResourceID = Annotated[str, APIPath(pattern=r"^[a-z0-9-]{1,64}$")]

    @app.get("/v1/documents/{resource_id}", response_model=Document)
    def read_document(resource_id: ResourceID, request: Request,
                      principal: Annotated[Principal, Depends(identity)]):
        request.state.context["resource"] = resource_id
        with app.state.sessions.checkpoint(request.state.session_ticket), app.state.lock:
            raw_doc = app.state.documents.get(resource_id)
            authorize(request, principal, raw_doc, "read")
            remember(request, [raw_doc], "read")
            return deepcopy(raw_doc)

    @app.patch("/v1/documents/{resource_id}", response_model=Document)
    def patch_document(resource_id: ResourceID, patch: DocumentPatch, request: Request,
                       principal: Annotated[Principal, Depends(identity)]):
        request.state.context["resource"] = resource_id
        changes = patch.model_dump(exclude_none=True, exclude={"expected_version"})
        if not changes:
            raise HTTPException(422, "No editable fields")
        with app.state.sessions.checkpoint(request.state.session_ticket) as lease, app.state.lock:
            raw_doc = app.state.documents.get(resource_id)
            authorize(request, principal, raw_doc, "write")
            if patch.expected_version != raw_doc["version"]:
                request.state.context["reason"] = "version_conflict"
                raise HTTPException(409, "Version conflict")
            updated = {**raw_doc, **changes, "version":raw_doc["version"]+1}
            validated = Document.model_validate(updated).model_dump()
            lease.check()
            app.state.documents[resource_id] = validated
            request.state.context["mutation_committed"] = True
            remember(request, [updated], "write")
            return deepcopy(updated)

    return app


def demo_tokens(app):
    """Local trusted issuer. No HTTP issuance route or user-selectable claims."""
    raw = json.loads((ROOT / "fixtures/principals.json").read_text(encoding="utf-8"))
    return {name:app.state.sessions.issue(Principal.model_validate(value)) for name,value in raw.items()}
