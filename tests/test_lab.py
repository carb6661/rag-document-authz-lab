import json
from pathlib import Path
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from doclab.api import ROOT, create_app, demo_tokens
from doclab.experiment import experiment
from doclab.models import Document, Principal
from doclab.security import Sessions, decide

PRINCIPALS = json.loads((ROOT/"fixtures/principals.json").read_text(encoding="utf-8"))
DOCS = {d["id"]:d for d in json.loads((ROOT/"fixtures/documents.json").read_text(encoding="utf-8"))}
PERMISSIONS = {
    "alice-editor":{"doc-a-alice":{"read","write"}},
    "alice-reader":{"doc-a-alice":{"read"}},
    "bob-editor":{"doc-a-bob":{"read","write"}},
    "admin-a":{"doc-a-alice":{"read","write"},"doc-a-bob":{"read","write"}},
    "alice-b":{"doc-b-alice":{"read","write"}}
}
MATRIX = [(actor, doc, action, action in PERMISSIONS[actor].get(doc,set()))
          for actor in PRINCIPALS for doc in DOCS for action in ("read","write")]


@pytest.fixture
def setup():
    app = create_app()
    tokens = demo_tokens(app)
    with TestClient(app) as client:
        yield app, client, tokens


def headers(tokens, actor="alice-editor"):
    return {"Authorization":"Bearer "+tokens[actor]}


@pytest.mark.parametrize("actor,doc,action,allowed", MATRIX)
def test_authorization_matrix(actor, doc, action, allowed):
    decision = decide(Principal.model_validate(PRINCIPALS[actor]), Document.model_validate(DOCS[doc]), action)
    assert decision.allowed is allowed


@pytest.mark.parametrize("actor,doc,action,allowed", MATRIX)
def test_api_authorization_matrix(setup, actor, doc, action, allowed):
    app, client, tokens = setup
    before = json.loads(json.dumps(app.state.documents))
    if action == "read":
        response = client.get("/v1/documents/"+doc, headers=headers(tokens,actor))
    else:
        response = client.patch("/v1/documents/"+doc, headers=headers(tokens,actor),
                                json={"text":"原创合成更新","expected_version":1})
    expected = 200 if allowed else (403 if actor == "alice-reader" and doc == "doc-a-alice" else 404)
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"
    assert app.state.audit[-1]["allowed"] is allowed
    if not allowed or action == "read":
        assert app.state.documents == before


def test_experiment_and_checked_in_evidence():
    actual = experiment()
    assert actual["cases"] == 13
    assert actual["all_expectations_met"]
    expected = json.loads((ROOT/"examples/report.json").read_text(encoding="utf-8"))
    assert actual == expected


def test_session_expiry_boundary_and_revocation():
    now = [100]
    sessions = Sessions(clock=lambda:now[0])
    p = Principal.model_validate(PRINCIPALS["alice-editor"])
    issued = sessions.issue(p, ttl=2)
    assert sessions.resolve(issued) == p
    assert issued not in sessions._items
    now[0] = 102
    assert sessions.resolve(issued) is None
    another = sessions.issue(p)
    sessions.revoke(another)
    assert sessions.resolve(another) is None
    sessions.revoke(None)


@pytest.mark.parametrize("ttl", [0,3601,True,"10"])
def test_invalid_session_ttl(ttl):
    with pytest.raises(ValueError):
        Sessions().issue(Principal.model_validate(PRINCIPALS["alice-editor"]), ttl=ttl)


def test_changed_and_other_session_tokens(setup):
    app, client, tokens = setup
    token = tokens["alice-editor"]
    changed = ("A" if token[0] != "A" else "B") + token[1:]
    external = Sessions().issue(Principal.model_validate(PRINCIPALS["alice-editor"]))
    for bad in [changed,external,"invalid","A"*5000]:
        response = client.get("/v1/documents/doc-a-alice",headers={"Authorization":"Bearer "+bad})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"


def test_no_credentials_and_wrong_scheme(setup):
    _,client,_ = setup
    for value in [None, "Basic arbitrary", "Bearer"]:
        response = client.get("/v1/documents/doc-a-alice",headers={} if value is None else {"Authorization":value})
        assert response.status_code == 401


def test_request_headers_cannot_change_identity(setup):
    _,client,tokens = setup
    response = client.get("/v1/documents/doc-b-alice",headers={
        **headers(tokens),"X-Tenant-ID":"tenant-b","X-Role":"tenant_admin","X-User-ID":"demo-carol"})
    assert response.status_code == 404


def test_foreign_and_missing_have_same_public_response(setup):
    _,client,tokens = setup
    foreign = client.get("/v1/documents/doc-a-bob",headers=headers(tokens))
    missing = client.get("/v1/documents/doc-unknown",headers=headers(tokens))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_lists_consistent_with_item_authorization(setup):
    _,client,tokens = setup
    for actor in PRINCIPALS:
        listing = client.get("/v1/documents",headers=headers(tokens,actor)).json()["documents"]
        visible = {d["id"] for d in listing}
        assert visible == set(PERMISSIONS[actor])
        assert all(d["tenant_id"] == PRINCIPALS[actor]["tenant_id"] for d in listing)


def test_list_query_cannot_select_foreign_tenant(setup):
    _,client,tokens=setup
    result=client.get("/v1/documents?tenant_id=tenant-b&owner_id=demo-carol",headers=headers(tokens))
    assert [d["id"] for d in result.json()["documents"]] == ["doc-a-alice"]


@pytest.mark.parametrize("extra", [{"owner_id":"demo-alice"},{"tenant_id":"tenant-b"},{"id":"new"},{"role":"tenant_admin"}])
def test_mass_assignment_rejected_without_mutation(setup, extra):
    app,client,tokens = setup
    before = json.loads(json.dumps(app.state.documents))
    response = client.patch("/v1/documents/doc-a-alice",headers=headers(tokens),
                            json={"text":"PRIVATE_MARKER","expected_version":1,**extra})
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    assert app.state.documents == before


@pytest.mark.parametrize("body", [{"expected_version":1},{"text":" ","expected_version":1},
    {"text":"a","expected_version":True},{"text":"a","expected_version":"1"},
    {"text":"a"*10001,"expected_version":1},{"text":"\x00","expected_version":1},
    {"text":"\ud800","expected_version":1}])
def test_input_validation(setup, body):
    app,client,tokens = setup
    # httpx JSON transport rejects lone surrogates before dispatch; use ASCII JSON.
    response = client.patch("/v1/documents/doc-a-alice",headers={**headers(tokens),"Content-Type":"application/json"},
                            content=json.dumps(body).encode("ascii"))
    assert response.status_code == 422
    assert app.state.documents["doc-a-alice"]["version"] == 1


def test_optimistic_concurrency_and_immutable_fields(setup):
    app,client,tokens = setup
    def update(text):
        return client.patch("/v1/documents/doc-a-alice",headers=headers(tokens),
                            json={"text":text,"expected_version":1}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(update,["first","second"]))
    assert sorted(statuses) == [200,409]
    current = app.state.documents["doc-a-alice"]
    assert current["version"] == 2
    assert (current["tenant_id"],current["owner_id"]) == ("tenant-a","demo-alice")
    assert any(row["reason"] == "version_conflict" for row in app.state.audit)


def test_audit_omits_credentials_and_content(setup):
    app,client,tokens = setup
    response = client.patch("/v1/documents/doc-a-alice",
        headers={**headers(tokens),"X-Request-ID":"user-controlled"},
        json={"text":"PRIVATE_MARKER","expected_version":1})
    row = dict(app.state.audit[-1])
    assert row["request_id"] == response.headers["x-request-id"] != "user-controlled"
    encoded = json.dumps(row)
    assert "PRIVATE_MARKER" not in encoded
    assert tokens["alice-editor"] not in encoded
    assert row["actor"] == "demo-alice" and row["status"] == 200


def test_audit_buffer_limit(setup):
    app,client,tokens = setup
    for _ in range(260):
        client.get("/v1/documents/doc-a-alice",headers=headers(tokens))
    assert len(app.state.audit) == 256


def test_body_limit_media_type_and_host(setup):
    _,client,tokens = setup
    assert client.get("/health",headers={"host":"evil.example"}).status_code == 400
    assert client.patch("/v1/documents/doc-a-alice",headers=headers(tokens),content="raw").status_code == 415
    response = client.patch("/v1/documents/doc-a-alice",headers={**headers(tokens),"Content-Type":"application/json"},content=b"x"*65537)
    assert response.status_code == 413


def test_revoked_session_immediately_denied(setup):
    app,client,tokens = setup
    app.state.sessions.revoke(tokens["alice-editor"])
    assert client.get("/v1/documents/doc-a-alice",headers=headers(tokens)).status_code == 401


def test_expired_session_denied_over_api():
    now=[100]
    sessions=Sessions(clock=lambda:now[0])
    app=create_app(sessions=sessions)
    token=sessions.issue(Principal.model_validate(PRINCIPALS["alice-editor"]),ttl=1)
    now[0]=101
    with TestClient(app) as client:
        assert client.get("/v1/documents/doc-a-alice",headers={"Authorization":"Bearer "+token}).status_code==401


def test_default_hardened_no_issuer_or_delete_route(setup):
    _,client,_=setup
    assert client.get("/health").json()["mode"] == "hardened"
    assert client.post("/v1/token",json={"role":"tenant_admin"}).status_code==404
    assert client.delete("/v1/documents/doc-a-alice").status_code==405


def test_unknown_action_and_missing_resource_fail_closed():
    p=Principal.model_validate(PRINCIPALS["admin-a"])
    assert not decide(p,Document.model_validate(DOCS["doc-a-alice"]),"delete").allowed
    assert not decide(p,None,"read").allowed


def test_cli_has_no_unsafe_server_switch():
    result=subprocess.run([sys.executable,"-m","doclab","serve","--unsafe"],
                          cwd=ROOT,capture_output=True,encoding="utf-8",timeout=30)
    assert result.returncode==2


def test_fixture_data_is_synthetic():
    for p in PRINCIPALS.values():
        assert p["user_id"].startswith("demo-")
    for d in DOCS.values():
        assert "原创演示" in d["text"]


def test_documentation_links():
    for path in [ROOT/"README.md",ROOT/"SECURITY.md",*(ROOT/"docs").glob("*.md")]:
        for target in re.findall(r"\]\(([^)]+)\)",path.read_text(encoding="utf-8")):
            if not target.startswith(("https://","http://","#")):
                assert (path.parent/target.split("#",1)[0]).exists(),target
