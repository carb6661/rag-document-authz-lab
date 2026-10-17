"""Finite local race probes. No external targets, credentials or persistent data."""
import json
from fastapi.testclient import TestClient
from . import retrieval
from .api import create_app, demo_tokens


def observations():
    results = {}
    for scenario in ("revoke_during_scoring", "change_version_during_scoring", "change_acl_during_scoring"):
        app = create_app()
        values = demo_tokens(app)
        original = retrieval.score_document
        def intervening(document, terms):
            if scenario == "revoke_during_scoring":
                app.state.sessions.revoke_subject("tenant-a","demo-alice")
            else:
                with app.state.lock:
                    current = app.state.documents["doc-a-alice"]
                    if scenario == "change_version_during_scoring":
                        current["text"] = "原创演示：更新后的合成正文。"
                        current["version"] += 1
                    else:
                        current["owner_id"] = "demo-bob"
            return original(document, terms)
        retrieval.score_document = intervening
        try:
            with TestClient(app) as client:
                response = client.post("/v1/retrieve",
                    headers={"Authorization":"Bearer "+values["alice-editor"]},
                    json={"query":"原创演示"})
            payload = response.json()
            hits = payload.get("hits", [])
            results[scenario] = {"status":response.status_code, "returned_hits":len(hits),
                "returned_version":hits[0]["version"] if hits else None,
                "live_version":app.state.documents["doc-a-alice"]["version"]}
        finally:
            retrieval.score_document = original

    app = create_app()
    values = demo_tokens(app)
    method = "authenticate" if hasattr(app.state.sessions,"authenticate") else "resolve"
    original = getattr(app.state.sessions, method)
    def revoke_after_identity(value):
        identity = original(value)
        app.state.sessions.revoke(values["alice-editor"])
        return identity
    setattr(app.state.sessions, method, revoke_after_identity)
    with TestClient(app) as client:
        response = client.patch("/v1/documents/doc-a-alice",
            headers={"Authorization":"Bearer "+values["alice-editor"]},
            json={"text":"原创演示：不应提交的合成变更。","expected_version":1})
    results["revoke_before_write_checkpoint"] = {"status":response.status_code,
        "document_changed":app.state.documents["doc-a-alice"]["version"] != 1}
    return results


if __name__ == "__main__":
    print(json.dumps(observations(),ensure_ascii=False,indent=2))
