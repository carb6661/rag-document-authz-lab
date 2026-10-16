import asyncio
from copy import deepcopy
import json

from fastapi.testclient import TestClient
import pytest

from doclab import api, retrieval
from doclab.api import ROOT, create_app, demo_tokens
from doclab.diagnostics import probes
from doclab.ingress import BodyLimit
from doclab.models import Principal
from doclab.security import SessionCapacityError, Sessions


@pytest.fixture
def setup():
    app = create_app()
    values = demo_tokens(app)
    with TestClient(app) as client:
        yield app, client, values


def headers(values, actor="alice-editor"):
    return {"Authorization":"Bearer "+values[actor], "Content-Type":"application/json"}


@pytest.mark.parametrize("body", [
    b'{"text":"first","text":"last","expected_version":1}',
    b'{"text":"first","expected_version":1,"expected_version":2}',
    b'{"text":{"nested":1,"nested":2},"expected_version":1}',
    b'{"text":NaN,"expected_version":1}',
    b'{"text":Infinity,"expected_version":1}',
    b'{"text":1e999,"expected_version":1}',
    b'[]', b'null', b'{"text":"a","expected_version":1,}', b"\xff",
])
def test_strict_json_rejected_without_mutation(setup, body):
    app, client, values = setup
    before = deepcopy(app.state.documents)
    response = client.patch("/v1/documents/doc-a-alice", content=body, headers=headers(values))
    assert response.status_code == 422
    assert app.state.documents == before
    assert app.state.audit[-1]["reason"] == "strict_json_rejected"
    assert "first" not in response.text


def test_duplicate_authentication_headers(setup):
    app,client,values=setup
    response=client.get("/v1/documents/doc-a-alice",headers=[
        ("Authorization","Bearer "+values["alice-editor"]),
        ("Authorization","Bearer "+values["alice-b"])])
    assert response.status_code==400
    assert app.state.audit[-1]["reason"]=="ambiguous_headers"
    assert app.state.audit[-1]["actor"] is None


def run_gate(messages=None, *, message_delay=0, header_items=None, **limits):
    captured = []
    calls = [0]
    forwarded = []
    async def receive():
        if message_delay:
            await asyncio.sleep(message_delay)
        index = calls[0]
        calls[0] += 1
        return messages[index]
    async def send(message):
        captured.append(message)
    async def downstream(scope, receive, send):
        forwarded.append(await receive())
        await send({"type":"http.response.start","status":204,"headers":[]})
        await send({"type":"http.response.body","body":b""})
    async def run():
        await BodyLimit(downstream,**limits)(
            {"type":"http","method":"GET","headers":header_items or []},receive,send)
    asyncio.run(run())
    return calls[0], captured, forwarded


def test_empty_frames_are_bounded():
    messages = [{"type":"http.request","body":b"","more_body":True}]*20
    calls, captured, forwarded = run_gate(messages, max_frames=4)
    assert calls==5
    assert captured[0]["status"]==413
    assert not forwarded


def test_small_fragments_replayed_once():
    messages=[{"type":"http.request","body":b"a","more_body":True},
              {"type":"http.request","body":b"b","more_body":False}]
    calls,captured,forwarded=run_gate(messages)
    assert calls==2 and captured[0]["status"]==204
    assert forwarded == [{"type":"http.request","body":b"ab","more_body":False}]


def test_body_deadline():
    calls,captured,forwarded=run_gate(
        [{"type":"http.request","body":b"","more_body":False}],
        message_delay=0.1,read_timeout=0.01)
    assert calls==0
    assert captured[0]["status"]==408
    assert not forwarded


def test_byte_limit_boundary():
    messages=[{"type":"http.request","body":b"1234","more_body":False}]
    assert run_gate(messages,max_body=4)[1][0]["status"]==204
    assert run_gate(messages,max_body=3)[1][0]["status"]==413


@pytest.mark.parametrize("key",[b"authorization",b"content-type",b"content-length",b"host"])
def test_ambiguous_sensitive_headers_rejected_before_read(key):
    calls,captured,forwarded=run_gate(
        [{"type":"http.request","body":b"","more_body":False}],
        header_items=[(key,b"first"),(key,b"second")])
    assert calls==0 and captured[0]["status"]==400 and not forwarded


@pytest.mark.parametrize("limits", [
    {"max_body":True}, {"max_frames":0}, {"read_timeout":0}, {"read_timeout":float("inf")}])
def test_invalid_ingress_configuration(limits):
    with pytest.raises(ValueError):
        BodyLimit(None,**limits)


def test_unexpected_error_audited_without_sensitive_echo(setup, monkeypatch):
    app,client,values=setup
    def broken(*args,**kwargs):
        raise RuntimeError("DO_NOT_ECHO_INTERNAL_MARKER")
    monkeypatch.setattr(api,"decide",broken)
    response=client.get("/v1/documents/doc-a-alice",headers=headers(values))
    assert response.status_code==500
    assert "DO_NOT_ECHO_INTERNAL_MARKER" not in response.text
    record=app.state.audit[-1]
    assert record["reason"]=="internal_error"
    assert record["status"]==500 and not record["allowed"]
    assert record["request_id"]==response.headers["x-request-id"]
    assert response.headers["cache-control"]=="no-store"
    assert "DO_NOT_ECHO_INTERNAL_MARKER" not in json.dumps(record)


def test_audit_sequence_timestamp_and_overwrite_count(setup):
    app,client,values=setup
    for _ in range(260):
        client.get("/v1/documents/doc-a-alice",headers=headers(values))
    assert app.state.audit_meta=={"sequence":260,"dropped":4}
    assert app.state.audit[0]["sequence"]==5
    assert app.state.audit[-1]["sequence"]==260
    assert app.state.audit[-1]["timestamp"].endswith("+00:00")


def test_session_cleanup_capacity_and_no_active_eviction():
    now=[100]
    sessions=Sessions(clock=lambda:now[0],max_sessions=2)
    principal=Principal(user_id="demo-alice",tenant_id="tenant-a",role="editor")
    first=sessions.issue(principal,ttl=1)
    second=sessions.issue(principal,ttl=10)
    with pytest.raises(SessionCapacityError):
        sessions.issue(principal)
    assert sessions.resolve(first)==principal and sessions.resolve(second)==principal
    now[0]=102
    third=sessions.issue(principal)
    assert len(sessions._items)==2
    assert sessions.resolve(first) is None
    assert sessions.resolve(second)==principal and sessions.resolve(third)==principal


def test_bulk_revocation_is_tenant_scoped():
    sessions=Sessions()
    first=Principal(user_id="demo-alice",tenant_id="tenant-a",role="editor")
    other=Principal(user_id="demo-alice",tenant_id="tenant-b",role="editor")
    tokens=[sessions.issue(first),sessions.issue(first),sessions.issue(other)]
    assert sessions.revoke_subject("tenant-a","demo-alice")==2
    assert sessions.resolve(tokens[0]) is None and sessions.resolve(tokens[1]) is None
    assert sessions.resolve(tokens[2])==other
    sessions.revoke("\ud800")


def test_purge_and_invalid_capacity():
    now=[10]
    sessions=Sessions(clock=lambda:now[0])
    p=Principal(user_id="demo",tenant_id="tenant-a",role="reader")
    sessions.issue(p,ttl=1)
    now[0]=11
    assert sessions.purge_expired()==1
    for value in [True,0,-1]:
        with pytest.raises(ValueError):
            Sessions(max_sessions=value)


@pytest.mark.parametrize("actor,expected",[
    ("alice-editor",{"doc-a-alice"}),("alice-reader",{"doc-a-alice"}),
    ("bob-editor",{"doc-a-bob"}),("admin-a",{"doc-a-alice","doc-a-bob"}),
    ("alice-b",{"doc-b-alice"})])
def test_retrieval_authorization_matrix(setup, actor, expected):
    _,client,values=setup
    response=client.post("/v1/retrieve",headers=headers(values,actor),
                         json={"query":"原创演示","top_k":10})
    assert response.status_code==200
    assert {hit["document_id"] for hit in response.json()["hits"]}==expected


def test_rejected_documents_never_reach_scorer(setup,monkeypatch):
    _,client,values=setup
    seen=[]
    original=retrieval.score_document
    def observed(document,terms):
        seen.append(document["id"])
        return original(document,terms)
    monkeypatch.setattr(retrieval,"score_document",observed)
    response=client.post("/v1/retrieve",headers=headers(values),json={"query":"同租户"})
    assert response.status_code==200 and response.json()["hits"]==[]
    assert seen==["doc-a-alice"]


def test_retrieval_snapshot_is_not_live_store_reference(setup,monkeypatch):
    app,client,values=setup
    original=retrieval.score_document
    def mutate_snapshot(document,terms):
        document["text"]="only the snapshot changes"
        return original(document,terms)
    monkeypatch.setattr(retrieval,"score_document",mutate_snapshot)
    before=deepcopy(app.state.documents)
    client.post("/v1/retrieve",headers=headers(values),json={"query":"snapshot"})
    assert app.state.documents==before


def test_retrieval_version_citation_and_revocation(setup):
    app,client,values=setup
    changed=client.patch("/v1/documents/doc-a-alice",headers=headers(values),
        json={"text":"检索版本更新标记","expected_version":1})
    assert changed.status_code==200
    response=client.post("/v1/retrieve",headers=headers(values),json={"query":"更新标记"})
    hit=response.json()["hits"][0]
    assert hit["version"]==2
    assert hit["citation"]=={"document_id":"doc-a-alice","version":2}
    app.state.sessions.revoke_subject("tenant-a","demo-alice")
    assert client.post("/v1/retrieve",headers=headers(values),json={"query":"更新标记"}).status_code==401


@pytest.mark.parametrize("payload",[
    {"query":" "},{"query":"a","top_k":True},{"query":"a","top_k":0},
    {"query":"a","top_k":11},{"query":"a","tenant_id":"tenant-b"},
    {"query":"a","owner_id":"demo-bob"},{"query":"a","role":"tenant_admin"},
    {"query":"a b c d e f g h i"},{"query":"a"*129},{"query":"\ud800"}
], ids=["blank","bool-k","zero-k","large-k","tenant","owner","role","terms","length","surrogate"])
def test_retrieval_input_validation(setup,payload):
    _,client,values=setup
    response=client.post("/v1/retrieve",headers=headers(values),
                         content=json.dumps(payload).encode("ascii"))
    assert response.status_code==422


def test_retrieval_needs_authentication(setup):
    _,client,_=setup
    assert client.post("/v1/retrieve",json={"query":"原创演示"}).status_code==401


def test_retrieval_top_k_and_stable_ties(setup):
    _,client,values=setup
    response=client.post("/v1/retrieve",headers=headers(values,"admin-a"),
                         json={"query":"原创演示","top_k":1})
    assert len(response.json()["hits"])==1
    assert response.json()["hits"][0]["document_id"]=="doc-a-alice"


def test_inflight_revocation_snapshot_limitation(setup,monkeypatch):
    app,client,values=setup
    original=retrieval.score_document
    def revoke_during_score(document,terms):
        app.state.sessions.revoke_subject("tenant-a","demo-alice")
        return original(document,terms)
    monkeypatch.setattr(retrieval,"score_document",revoke_during_score)
    response=client.post("/v1/retrieve",headers=headers(values),json={"query":"原创演示"})
    # Known, documented boundary: this request already holds its identity snapshot.
    assert response.status_code==200 and len(response.json()["hits"])==1
    assert client.post("/v1/retrieve",headers=headers(values),json={"query":"原创演示"}).status_code==401


def test_before_after_probes_match_checked_evidence():
    current=probes()
    expected=json.loads((ROOT/"examples/hardening-v020.json").read_text(encoding="utf-8"))
    assert current==expected["observations"]
    baseline=json.loads((ROOT/"examples/baseline-v010.json").read_text(encoding="utf-8"))["observations"]
    assert baseline["duplicate_json"]["status"]==200 and current["duplicate_json"]["status"]==422
    assert baseline["unexpected_failure"]["audit_events"]==0 and current["unexpected_failure"]["audit_events"]==1
