"""Fixed local requests, never a caller-supplied target or real account."""
import json
from fastapi.testclient import TestClient
from .api import ROOT, create_app, demo_tokens


def experiment():
    cases = json.loads((ROOT / "fixtures/cases.json").read_text(encoding="utf-8"))
    rows, evidence = [], []
    for case in cases:
        row = {"case":case["id"]}
        for mode in ("unsafe", "hardened"):
            app = create_app(unsafe=mode == "unsafe")
            tokens = demo_tokens(app)
            headers = {"Authorization":"Bearer "+tokens[case["actor"]]} if case["actor"] else {}
            path = "/v1/documents" + ("/"+case["resource"] if case["resource"] else "")
            before = {k:v.copy() for k,v in app.state.documents.items()}
            with TestClient(app) as client:
                response = client.request(case["method"], path, headers=headers, **({"json":case["body"]} if "body" in case else {}))
            status = response.status_code
            row[mode+"_status"] = status
            row[mode+"_matches_expected"] = status == case[mode+"_status"]
            if mode+"_count" in case:
                count = len(response.json()["documents"])
                row[mode+"_visible_documents"] = count
                row[mode+"_matches_expected"] &= count == case[mode+"_count"]
            if case["method"] == "PATCH":
                row[mode+"_store_changed"] = app.state.documents != before
            audit = dict(app.state.audit[-1])
            audit.pop("request_id")  # Per-request UUID remains available in live API.
            evidence.append({"case":case["id"], "mode":mode, **audit})
        rows.append(row)
    return {"schema_version":1, "scope":"synthetic in-process experiment only",
            "cases":len(rows), "all_expectations_met":all(r["unsafe_matches_expected"] and r["hardened_matches_expected"] for r in rows),
            "results":rows, "audit_evidence":evidence,
            "limitations":["Not a production authentication service or RAG retrieval system.",
                           "No real user data, external target or model involved.",
                           "Passing cases do not prove authorization completeness."]}
