from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import httpx
import socket
from urllib.parse import urlparse
import time

app = FastAPI()

origins = ["*"]  # allow all for now

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str


@app.post("/scan")
async def scan(req: ScanRequest):
    url = req.target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # default to HTTP if protocol missing

    parsed = urlparse(url)
    host = parsed.hostname

    # Resolve IP
    try:
        ip_address = socket.gethostbyname(host)
    except Exception:
        ip_address = "Could not resolve"

    start = time.time()
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(url)
        duration_ms = int((time.time() - start) * 1000)

        # Extract title
        text = resp.text or ""
        title = ""
        lower = text.lower()
        start_tag = lower.find("<title>")
        end_tag = lower.find("</title>")
        if start_tag != -1 and end_tag != -1:
            title = text[start_tag + 7:end_tag].strip()

        # Headers
        headers = dict(resp.headers)
        interesting = {
            k: headers[k]
            for k in headers
            if k.lower()
            in [
                "server",
                "x-powered-by",
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
            ]
        }

        # Simple security hints
        hints = []
        keys_lower = [k.lower() for k in headers.keys()]
        if not url.startswith("https://"):
            hints.append("Target is not using HTTPS (you entered HTTP).")
        if "content-security-policy" not in keys_lower:
            hints.append("Missing Content-Security-Policy header.")
        if "strict-transport-security" not in keys_lower:
            hints.append("Missing HSTS (Strict-Transport-Security) header.")

        return {
            "target": url,
            "host": host,
            "ip": ip_address,
            "status_code": resp.status_code,
            "response_time_ms": duration_ms,
            "title": title,
            "interesting_headers": interesting,
            "hints": hints,
        }

    except Exception as e:
        return {
            "target": url,
            "host": host,
            "ip": ip_address,
            "error": str(e),
        }
