"""Deterministic local interleavings, not timing/throughput claims."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import threading

from fastapi.testclient import TestClient
import pytest

from doclab import api, retrieval
from doclab.api import ROOT, create_app, demo_tokens
from doclab.models import Principal
from doclab.publication import PublicationGuard
from doclab.race_diagnostics import observations
from doclab.security import Sessions, SessionInvalidatedError, SessionTicket


@pytest.fixture
def setup():
    now = [100]
    app = create_app(sessions=Sessions(clock=lambda:now[0]))
    values = demo_tokens(app)
    with TestClient(app) as client:
        yield app, client, {"Authorization":"Bearer "+values["alice-editor"]}, now


@pytest.mark.parametrize("change,status", [
    ("revoke",401), ("expire",401), ("version",409), ("owner",409),
    ("tenant",409), ("delete",409),
])
def test_interleaving_before_publication(setup, monkeypatch, change, status):
    app, client, headers, now = setup
    original = retrieval.score_document
    def intervene(document, terms):
        if change == "revoke":
            app.state.sessions.revoke_subject("tenant-a","demo-alice")
        elif change == "expire":
            now[0] = 1000
        else:
            with app.state.lock:
                raw = app.state.documents[document["id"]]
                if change == "version":
                    raw["version"] += 1
                elif change == "owner":
                    raw["owner_id"] = "demo-bob"  # Deliberately no version bump.
                elif change == "tenant":
                    raw["tenant_id"] = "tenant-b"
                else:
                    del app.state.documents[document["id"]]
        return original(document, terms)
    monkeypatch.setattr(retrieval,"score_document",intervene)
    response = client.post("/v1/retrieve",headers=headers,json={"query":"原创演示"})
    assert response.status_code == status
    assert "hits" not in response.json() and "原创演示" not in response.text
    event = app.state.audit[-1]
    assert event["status"] == status and not event["allowed"]
    assert event["reason"].startswith("publication_")
    assert not event["mutation_committed"]
    assert response.headers["cache-control"] == "no-store"
    if status == 401:
        assert response.headers["www-authenticate"] == "Bearer"


def test_empty_retrieval_also_rechecks_session(setup, monkeypatch):
    app,client,headers,_ = setup
    original = retrieval.rank_authorized
    def revoke_then_empty(*args):
        app.state.sessions.revoke_subject("tenant-a","demo-alice")
        return original(*args)
    monkeypatch.setattr(api,"rank_authorized",revoke_then_empty)
    response = client.post("/v1/retrieve",headers=headers,json={"query":"never-matches"})
    assert response.status_code == 401 and "hits" not in response.json()


@pytest.mark.parametrize("method,path,payload",[
    ("GET","/v1/documents",None),
    ("GET","/v1/documents/doc-a-alice",None),
    ("POST","/v1/retrieve",{"query":"原创演示"}),
    ("PATCH","/v1/documents/doc-a-alice",{"text":"synthetic edit","expected_version":1}),
])
def test_revoked_after_identity_before_endpoint(setup,monkeypatch,method,path,payload):
    app,client,headers,_ = setup
    before = deepcopy(app.state.documents)
    original = app.state.sessions.authenticate
    def authenticate_then_revoke(value):
        ticket = original(value)
        app.state.sessions.revoke_subject("tenant-a","demo-alice")
        return ticket
    monkeypatch.setattr(app.state.sessions,"authenticate",authenticate_then_revoke)
    response = client.request(method,path,headers=headers,**({"json":payload} if payload else {}))
    assert response.status_code == 401 and app.state.documents == before
    assert app.state.audit[-1]["reason"] == "checkpoint_session_invalidated"
    assert not app.state.audit[-1]["mutation_committed"]


def test_expiry_while_document_validation_runs_prevents_write(setup,monkeypatch):
    app,client,headers,now = setup
    before = deepcopy(app.state.documents)
    original = api.decide
    def expire_inside_policy(*args,**kwargs):
        result = original(*args,**kwargs)
        now[0] = 1000  # Do not call a Sessions method while holding its lock.
        return result
    monkeypatch.setattr(api,"decide",expire_inside_policy)
    response = client.patch("/v1/documents/doc-a-alice",headers=headers,
        json={"text":"synthetic edit","expected_version":1})
    assert response.status_code == 401 and app.state.documents == before
    assert not app.state.audit[-1]["mutation_committed"]


def test_expiry_during_final_policy_check_drops_body(setup,monkeypatch):
    app,client,headers,now = setup
    original = api.decide
    calls = [0]
    def expire_on_publication(*args,**kwargs):
        result = original(*args,**kwargs)
        calls[0] += 1
        if calls[0] == 2:
            now[0] = 1000
        return result
    monkeypatch.setattr(api,"decide",expire_on_publication)
    response = client.get("/v1/documents/doc-a-alice",headers=headers)
    assert response.status_code == 401 and "text" not in response.json()
    assert calls[0] == 2


def test_revocation_after_write_commit_is_not_rollback(setup,monkeypatch):
    app,client,headers,_ = setup
    original = PublicationGuard.check
    def revoke_before_final_check(guard,scope):
        app.state.sessions.revoke_subject("tenant-a","demo-alice")
        return original(guard,scope)
    monkeypatch.setattr(PublicationGuard,"check",revoke_before_final_check)
    response = client.patch("/v1/documents/doc-a-alice",headers=headers,
        json={"text":"already committed synthetic edit","expected_version":1})
    assert response.status_code == 401
    assert app.state.documents["doc-a-alice"]["version"] == 2
    assert app.state.documents["doc-a-alice"]["text"] == "already committed synthetic edit"
    event = app.state.audit[-1]
    assert event["mutation_committed"] and not event["allowed"]
    assert event["reason"] == "publication_session_invalidated"


def test_revocation_after_final_checkpoint_cannot_recall_response(setup,monkeypatch):
    app,client,headers,_ = setup
    original = PublicationGuard.check
    def revoke_after_check(guard,scope):
        result = original(guard,scope)
        app.state.sessions.revoke_subject("tenant-a","demo-alice")
        return result
    monkeypatch.setattr(PublicationGuard,"check",revoke_after_check)
    response = client.get("/v1/documents/doc-a-alice",headers=headers)
    assert response.status_code == 200  # Explicit residual application/send boundary.
    assert client.get("/v1/documents/doc-a-alice",headers=headers).status_code == 401


@pytest.mark.parametrize("method,path,payload",[
    ("GET","/v1/documents",None),
    ("GET","/v1/documents/doc-a-alice",None),
    ("POST","/v1/retrieve",{"query":"原创演示"}),
])
def test_all_read_routes_recheck_acl_before_publication(setup,monkeypatch,method,path,payload):
    app,client,headers,_ = setup
    original = PublicationGuard.check
    def change_acl(guard,scope):
        with app.state.lock:
            app.state.documents["doc-a-alice"]["owner_id"] = "demo-bob"
        return original(guard,scope)
    monkeypatch.setattr(PublicationGuard,"check",change_acl)
    response = client.request(method,path,headers=headers,**({"json":payload} if payload else {}))
    assert response.status_code == 409 and "text" not in response.json()
    assert "原创演示" not in response.text


def test_publication_error_is_sanitized_and_audited(setup,monkeypatch):
    app,client,headers,_ = setup
    def broken(*args):
        raise RuntimeError("DO_NOT_ECHO_PUBLICATION_INTERNAL")
    monkeypatch.setattr(PublicationGuard,"check",broken)
    response = client.get("/v1/documents/doc-a-alice",headers=headers)
    assert response.status_code == 500 and "DO_NOT_ECHO" not in response.text
    assert app.state.audit[-1]["reason"] == "internal_error"
    assert app.state.audit[-1]["status"] == 500


def run_guard(*, failure=None, path="/v1/example", kind="http", status=200):
    messages = []
    checks = []
    async def downstream(scope,receive,send):
        await send({"type":"http.response.start","status":status,"headers":[]})
        await send({"type":"http.response.body","body":b"ORIGINAL_PRIVATE_BODY","more_body":True})
        await send({"type":"http.response.body","body":b"ORIGINAL_PRIVATE_TAIL"})
        await send({"type":"http.response.trailers","headers":[(b"x-private",b"original")]})
    guard = PublicationGuard(downstream,None,None,None,None)
    def check(scope):
        checks.append(scope)
        return failure
    guard.check = check
    async def receive():
        return {"type":"http.disconnect"}
    async def send(message):
        messages.append(message)
    scope = {"type":kind,"path":path,"state":{"context":{}},"headers":[]}
    asyncio.run(guard(scope,receive,send))
    return messages,checks,scope


@pytest.mark.parametrize("status",[401,409,500])
def test_publication_replaces_entire_body_and_trailers(status):
    messages,checks,scope = run_guard(failure=(status,"test_reason","generic error"))
    assert len(checks) == 1 and len(messages) == 2
    assert messages[0]["status"] == status
    assert json.loads(messages[1]["body"]) == {"detail":"generic error"}
    assert b"ORIGINAL_PRIVATE" not in repr(messages).encode()
    assert scope["state"]["context"]["reason"] == "test_reason"


@pytest.mark.parametrize("options",[{"status":404},{"path":"/health"},{"kind":"websocket"}])
def test_guard_does_not_recheck_denies_or_other_surfaces(options):
    messages,checks,_ = run_guard(failure=(500,"unexpected","unexpected"),**options)
    assert not checks and len(messages) == 4


def test_success_body_passes_without_replacement():
    messages,checks,_ = run_guard()
    assert len(checks) == 1 and messages[0]["status"] == 200
    assert messages[1]["body"] == b"ORIGINAL_PRIVATE_BODY"


def principal():
    return Principal(user_id="demo-alice",tenant_id="tenant-a",role="editor")


def test_ticket_lifecycle_and_lease_scope():
    now = [10]
    sessions = Sessions(clock=lambda:now[0])
    value = sessions.issue(principal(),ttl=10)
    ticket = sessions.authenticate(value)
    assert ticket.principal == principal() and sessions.resolve(value) == principal()
    assert ticket.identifier not in repr(ticket)
    with sessions.checkpoint(ticket) as lease:
        assert lease.check() == principal()
    with pytest.raises(RuntimeError):
        lease.check()
    sessions.revoke(value)
    with pytest.raises(SessionInvalidatedError), sessions.checkpoint(ticket):
        pass
    assert sessions.resolve(value) is None


@pytest.mark.parametrize("case",["expired","wrong-principal","wrong-type"])
def test_invalid_ticket_fails_closed(case):
    now = [10]
    sessions = Sessions(clock=lambda:now[0])
    ticket = sessions.authenticate(sessions.issue(principal(),ttl=10))
    if case == "expired":
        now[0] = 20
    elif case == "wrong-principal":
        ticket = SessionTicket(ticket.identifier,Principal(user_id="demo-bob",tenant_id="tenant-a",role="editor"))
    else:
        ticket = None
    with pytest.raises(SessionInvalidatedError), sessions.checkpoint(ticket):
        pass


def test_lease_rejects_another_thread():
    sessions = Sessions()
    ticket = sessions.authenticate(sessions.issue(principal()))
    with ThreadPoolExecutor(max_workers=1) as pool:
        with sessions.checkpoint(ticket) as lease:
            future = pool.submit(lease.check)
            with pytest.raises(RuntimeError):
                future.result(timeout=2)


def test_checkpoint_serializes_revocation_without_sleep():
    sessions = Sessions()
    ticket = sessions.authenticate(sessions.issue(principal()))
    attempting = threading.Event()
    done = threading.Event()
    order = []
    def revoke():
        attempting.set()
        sessions.revoke_subject("tenant-a","demo-alice")
        order.append("revoked")
        done.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with sessions.checkpoint(ticket) as lease:
            future = pool.submit(revoke)
            assert attempting.wait(timeout=2)
            assert not done.is_set()
            assert lease.check() == principal()
            order.append("checked")
        future.result(timeout=2)
    assert order == ["checked","revoked"]
    with pytest.raises(SessionInvalidatedError), sessions.checkpoint(ticket):
        pass


def test_missing_publication_proof_and_identity_fail_closed():
    sessions = Sessions()
    ticket = sessions.authenticate(sessions.issue(principal()))
    guard = PublicationGuard(None,sessions,lambda:{},threading.Lock(),api.decide)
    assert guard.check({"state":{}})[0] == 401
    assert guard.check({"state":{"session_ticket":ticket}})[0] == 500
    assert guard.check({"state":{"session_ticket":ticket,"publication_docs":()}}) is None


def test_checkpoint_runs_off_event_loop_and_releases_locks_before_send():
    sessions = Sessions()
    ticket = sessions.authenticate(sessions.issue(principal()))
    document_lock = threading.Lock()
    thread_ids = []
    sent = []
    async def downstream(scope,receive,send):
        await send({"type":"http.response.start","status":200,"headers":[]})
        await send({"type":"http.response.body","body":b"{}"})
    guard = PublicationGuard(downstream,sessions,lambda:{},document_lock,api.decide)
    original = guard.check
    def observed(scope):
        thread_ids.append(threading.get_ident())
        return original(scope)
    guard.check = observed
    async def receive():
        return {"type":"http.disconnect"}
    async def send(message):
        for lock in (sessions._lock,document_lock):
            acquired = lock.acquire(blocking=False)
            assert acquired, "never hold a security lock across send"
            lock.release()
        sent.append(message)
    asyncio.run(guard({"type":"http","path":"/v1/example","state":{
        "session_ticket":ticket,"publication_docs":()}},receive,send))
    assert thread_ids[0] != threading.get_ident() and len(sent) == 2


def test_conservative_candidate_proof_can_reject_a_non_hit(setup,monkeypatch):
    app,client,_,_ = setup
    admin_value = app.state.sessions.issue(Principal(user_id="demo-admin",tenant_id="tenant-a",role="tenant_admin"))
    original = retrieval.score_document
    def change_other_candidate(document,terms):
        if document["id"] == "doc-a-alice":
            with app.state.lock:
                app.state.documents["doc-a-bob"]["version"] += 1
        return original(document,terms)
    monkeypatch.setattr(retrieval,"score_document",change_other_candidate)
    # No hit is required: any originally authorized candidate may invalidate the batch.
    response = client.post("/v1/retrieve",headers={"Authorization":"Bearer "+admin_value},
                           json={"query":"never-matches"})
    assert response.status_code == 409 and "hits" not in response.json()


def test_race_report_matches_actual_and_preserves_old_baseline():
    actual = observations()
    expected = json.loads((ROOT/"examples/races-v030.json").read_text(encoding="utf-8"))
    baseline = json.loads((ROOT/"examples/races-v020.json").read_text(encoding="utf-8"))
    assert actual == expected["observations"]
    assert baseline["observations"]["revoke_during_scoring"]["returned_hits"] == 1
    assert actual["revoke_during_scoring"]["returned_hits"] == 0
    assert baseline["observations"]["revoke_before_write_checkpoint"]["document_changed"]
    assert not actual["revoke_before_write_checkpoint"]["document_changed"]
