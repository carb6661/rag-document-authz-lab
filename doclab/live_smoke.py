"""Real HTTP against a fresh loopback hardened server; never prints session tokens."""
import json
import socket
import threading
import time
import httpx
import uvicorn
from .api import create_app, demo_tokens


def main():
    app = create_app()
    tokens = demo_tokens(app)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                         log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets":[sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("local server did not start")
            time.sleep(0.02)
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=10) as client:
            header = {"Authorization":"Bearer "+tokens["alice-editor"]}
            own = client.get("/v1/documents/doc-a-alice", headers=header)
            peer = client.get("/v1/documents/doc-a-bob", headers=header)
            other = client.get("/v1/documents/doc-b-alice", headers=header)
            listing = client.get("/v1/documents", headers=header)
            anonymous = client.get("/v1/documents/doc-a-alice")
            result = {"own_read":own.status_code, "peer_read":peer.status_code,
                      "cross_tenant_read":other.status_code, "anonymous":anonymous.status_code,
                      "visible_documents":len(listing.json()["documents"])}
            assert result == {"own_read":200,"peer_read":404,"cross_tenant_read":404,
                              "anonymous":401,"visible_documents":1}
            print(json.dumps({"live_http":"passed", **result}))
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        if thread.is_alive():
            raise RuntimeError("server failed to stop")


if __name__ == "__main__":
    main()
