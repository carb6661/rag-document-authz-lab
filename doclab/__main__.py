import argparse
import json
from .api import create_app, demo_tokens
from .experiment import experiment


def main(argv=None):
    parser = argparse.ArgumentParser(description="本地RAG文档对象授权实验；不连接外部目标。")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("experiment")
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if args.command == "experiment":
        report = experiment()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["all_expectations_met"] else 1
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    import uvicorn
    app = create_app()
    print("仅本地合成数据；以下会话15分钟有效，重启失效。不要公开或用于真实系统。", flush=True)
    print(json.dumps({"demo_sessions":demo_tokens(app)}, ensure_ascii=False, indent=2), flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
