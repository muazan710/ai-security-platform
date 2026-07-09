import argparse
import json
import os
import sys
from typing import Any

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field


BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000").rstrip("/")
MCP_API_KEY = os.getenv("MCP_API_KEY", "")
REQUEST_TIMEOUT = float(os.getenv("MCP_REQUEST_TIMEOUT", "20"))

app = FastAPI(title="AI Security MCP Server", version=os.getenv("APP_VERSION", "2.0.0"))


class URLSafetyRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    use_ai_agent: bool = True
    use_threat_intel: bool = True


class DomainIntelRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)


def _require_key(x_api_key: str | None) -> str:
    key = x_api_key or MCP_API_KEY
    if not key:
        raise HTTPException(status_code=401, detail="X-API-Key is required")
    return key


def _backend_post(path: str, payload: dict[str, Any], api_key: str) -> dict[str, Any]:
    response = requests.post(
        f"{BACKEND_URL}{path}",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )
    try:
        data = response.json()
    except ValueError:
        data = {"detail": response.text}
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", data))
    return data


def check_url_safety_tool(payload: URLSafetyRequest, api_key: str) -> dict[str, Any]:
    return _backend_post(
        "/predict",
        {
            "url": payload.url,
            "model_name": "RandomForest",
            "use_ai_agent": payload.use_ai_agent,
            "use_threat_intel": payload.use_threat_intel,
        },
        api_key,
    )


def get_domain_intel_tool(payload: DomainIntelRequest, api_key: str) -> dict[str, Any]:
    result = _backend_post(
        "/predict",
        {
            "url": f"https://{payload.domain}",
            "model_name": "RandomForest",
            "use_ai_agent": False,
            "use_threat_intel": True,
        },
        api_key,
    )
    return {
        "domain": payload.domain,
        "domain_exists": result.get("domain_exists"),
        "domain_age": result.get("domain_age"),
        "threat_intel": result.get("threat_intel", {}),
        "virustotal": result.get("virustotal", {}),
    }


@app.get("/health")
def health():
    return {"status": "ok", "backend_url": BACKEND_URL}


@app.post("/check_url_safety")
def check_url_safety(payload: URLSafetyRequest, x_api_key: str | None = Header(None, alias="X-API-Key")):
    return check_url_safety_tool(payload, _require_key(x_api_key))


@app.post("/get_domain_intel")
def get_domain_intel(payload: DomainIntelRequest, x_api_key: str | None = Header(None, alias="X-API-Key")):
    return get_domain_intel_tool(payload, _require_key(x_api_key))


@app.get("/sse")
def sse_health():
    def events():
        yield "event: tools\n"
        yield 'data: {"tools":["check_url_safety","get_domain_intel"]}\n\n'

    return StreamingResponse(events(), media_type="text/event-stream")


def run_stdio() -> None:
    api_key = MCP_API_KEY
    for line in sys.stdin:
        try:
            message = json.loads(line)
            tool = message.get("tool")
            arguments = message.get("arguments", {})
            if tool == "check_url_safety":
                result = check_url_safety_tool(URLSafetyRequest(**arguments), api_key)
            elif tool == "get_domain_intel":
                result = get_domain_intel_tool(DomainIntelRequest(**arguments), api_key)
            else:
                raise ValueError(f"Unknown tool: {tool}")
            print(json.dumps({"ok": True, "result": result}), flush=True)
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "8010")))
    args = parser.parse_args()

    if args.stdio:
        run_stdio()
    else:
        import uvicorn

        uvicorn.run("mcp_server:app", host=args.host, port=args.port)
