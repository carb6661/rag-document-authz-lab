"""Bounded ASGI ingestion with unambiguous headers and strict JSON objects."""
import asyncio
import json
import math
from starlette.responses import JSONResponse

MAX_BODY = 65_536
MAX_FRAMES = 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def no_constant(value):
    raise ValueError("nonstandard JSON constant")


class BodyLimit:
    def __init__(self, app, max_body=MAX_BODY, max_frames=MAX_FRAMES, read_timeout=5.0):
        if type(max_body) is not int or max_body < 1 or type(max_frames) is not int or max_frames < 1:
            raise ValueError("positive body/frame limits required")
        if type(read_timeout) not in (int, float) or not math.isfinite(read_timeout) or read_timeout <= 0:
            raise ValueError("positive finite read timeout required")
        self.app, self.max_body, self.max_frames, self.read_timeout = app, max_body, max_frames, read_timeout

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def reject(status, reason, detail):
            scope["gate_reason"] = reason
            await JSONResponse({"detail":detail}, status_code=status)(scope, receive, send)

        headers = scope.get("headers", [])
        for key in (b"authorization", b"content-type", b"content-length", b"host"):
            if sum(name.lower() == key for name, _ in headers) > 1:
                return await reject(400, "ambiguous_headers", "Ambiguous request headers")
        header_map = {name.lower():value for name, value in headers}
        needs_json = scope["method"] in ("PATCH", "POST")
        if needs_json and header_map.get(b"content-type", b"").split(b";")[0].strip().lower() != b"application/json":
            return await reject(415, "unsupported_media_type", "JSON required")

        body = bytearray()
        frames = 0
        deadline = asyncio.get_running_loop().time() + self.read_timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return await reject(408, "body_timeout", "Request body timeout")
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except TimeoutError:
                return await reject(408, "body_timeout", "Request body timeout")
            if message["type"] == "http.disconnect":
                scope["gate_reason"] = "client_disconnect"
                return
            frames += 1
            if frames > self.max_frames:
                return await reject(413, "frame_limit", "Too many request frames")
            payload = message.get("body", b"")
            if len(body) + len(payload) > self.max_body:
                return await reject(413, "body_limit", "Body too large")
            body.extend(payload)
            if not message.get("more_body", False):
                break

        if needs_json:
            try:
                parsed = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object,
                                    parse_constant=no_constant, parse_float=finite_float)
                if not isinstance(parsed, dict):
                    raise ValueError("JSON object required")
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                return await reject(422, "strict_json_rejected", "Invalid JSON object")
        # One bounded replay message, not a list of user-controlled frames.
        consumed = False
        async def replay():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type":"http.request", "body":bytes(body), "more_body":False}
            return {"type":"http.request", "body":b"", "more_body":False}
        await self.app(scope, replay, send)
