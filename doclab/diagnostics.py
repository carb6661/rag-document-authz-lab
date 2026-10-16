"""Small, synthetic regression probes; no external services or credentials."""
import asyncio
import json
from fastapi.testclient import TestClient
from . import api
from .api import create_app, demo_tokens
from .models import Principal
from .security import Sessions


def probes():
    observations = {}
    app = create_app()
    sessions = demo_tokens(app)
    header = {"Authorization":"Bearer "+sessions["alice-editor"], "Content-Type":"application/json"}
    with TestClient(app) as client:
        response = client.patch("/v1/documents/doc-a-alice", headers=header,
            content=b'{"text":"first","text":"last","expected_version":1}')
        observations["duplicate_json"] = {"status":response.status_code,
            "stored_text":app.state.documents["doc-a-alice"]["text"] if response.status_code==200 else "unchanged"}
        response = client.get("/v1/documents/doc-a-alice", headers=[
            ("Authorization","Bearer "+sessions["alice-editor"]),
            ("Authorization","Bearer "+sessions["alice-b"])])
        observations["duplicate_authorization"] = {"status":response.status_code}

    app = create_app()
    sessions = demo_tokens(app)
    original = api.decide
    def broken(*args, **kwargs):
        raise RuntimeError("SYNTHETIC_INTERNAL_ERROR")
    api.decide = broken
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/v1/documents/doc-a-alice",
                headers={"Authorization":"Bearer "+sessions["alice-editor"]})
        observations["unexpected_failure"] = {"status":response.status_code,
            "audit_events":len(app.state.audit), "request_id_present":"x-request-id" in response.headers,
            "no_store":response.headers.get("cache-control")=="no-store"}
    finally:
        api.decide = original

    now = [100]
    store = Sessions(clock=lambda:now[0])
    principal = Principal(user_id="demo-user", tenant_id="tenant-a", role="reader")
    for _ in range(3):
        store.issue(principal, ttl=1)
    now[0] = 102
    store.issue(principal, ttl=1)
    observations["expired_session_cleanup"] = {"entries_after_new_issue":len(store._items)}

    async def frames():
        count = 0
        received = []
        async def receive():
            nonlocal count
            count += 1
            return {"type":"http.request","body":b"","more_body":count<=1500}
        async def send(msg):
            received.append(msg)
        async def downstream(scope, receive, send):
            forwarded = 0
            while True:
                msg = await receive()
                forwarded += 1
                if not msg.get("more_body",False):
                    break
            received.append({"forwarded_frames":forwarded})
        await api.BodyLimit(downstream)({"type":"http","method":"GET","headers":[]},receive,send)
        return {"received_frames":count,
                "forwarded_frames":next((r["forwarded_frames"] for r in received if "forwarded_frames" in r),0),
                "status":next((r["status"] for r in received if r.get("type")=="http.response.start"),None)
                        if any(r.get("type")=="http.response.start" for r in received) else None}
    observations["empty_asgi_frames"] = asyncio.run(frames())
    return observations


if __name__ == "__main__":
    print(json.dumps(probes(),ensure_ascii=False,indent=2))
