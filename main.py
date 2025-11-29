from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import socket
from urllib.parse import urlparse
import time
import asyncio

app = FastAPI()

# Allow all origins (Vercel, localhost, etc.)
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str


# ---------- helpers ----------

COMMON_PORTS = [22, 80, 443, 21, 25]


async def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Try to connect to TCP port. Returns True if connect succeeds, False otherwise.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def scan_common_ports(host: str) -> dict:
    """
    Quickly check a small set of common ports.
    """
    results = {}
    tasks = []
    for p in COMMON_PORTS:
        tasks.append(check_port(host, p))
    statuses = await asyncio.gather(*tasks, return_exceptions=True)
    for port, status in zip(COMMON_PORTS, statuses):
        is_open = isinstance(status, bool) and status
        results[str(port)] = "open" if is_open else "closed"
    return results


async def fetch_robots(client: httpx.AsyncClient, scheme: str, host: str):
    """
    Try to fetch robots.txt and return some basic info.
    """
    base_scheme = scheme or "http"
    robots_url = f"{base_scheme}://{host}/robots.txt"
    info = {
        "url": robots_url,
        "found": False,
        "status_code": None,
        "preview": [],
    }
    try:
        resp = await client.get(robots_url, timeout=5.0)
        info["status_code"] = resp.status_code
        if resp.status_code == 200 and resp.text:
            info["found"] = True
            lines = resp.text.splitlines()
            # only show first few lines to keep response small
            info["preview"] = lines[:10]
    except Exception:
        # ignore robots errors; just return default info
        pass
    return info


def reverse_dns(ip: str) -> str | None:
    """
    Try to get reverse DNS (PTR) for the IP.
    """
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


# ---------- main endpoint ----------


@app.post("/scan")
async def scan(req: ScanRequest):
    url = req.target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # default to HTTP if protocol missing

    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc

    # Resolve IP
    try:
        ip_address = socket.gethostbyname(host)
    except Exception:
        ip_address = "Could not resolve"

    # Reverse DNS (optional)
    rdns_name = reverse_dns(ip_address) if ip_address and "Could not resolve" not in ip_address else None

    start = time.time()
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            # main HTTP request
            resp = await client.get(url)
            duration_ms = int((time.time() - start) * 1000)

            # Final URL (after redirects)
            final_url = str(resp.url)

            # Page title
            text = resp.text or ""
            title = ""
            lower = text.lower()
            start_tag = lower.find("<title>")
            end_tag = lower.find("</title>")
            if start_tag != -1 and end_tag != -1:
                title = text[start_tag + 7:end_tag].strip()

            # HTTP info
            status_code = resp.status_code
            status_family = f"{status_code // 100}xx"
            content_length = len(resp.content or b"")
            redirect_count = len(resp.history)
            is_https = final_url.startswith("https://")

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

            if not is_https:
                hints.append("Target is not using HTTPS.")
            if "content-security-policy" not in keys_lower:
                hints.append("Missing Content-Security-Policy header.")
            if "strict-transport-security" not in keys_lower:
                hints.append("Missing HSTS (Strict-Transport-Security) header.")
            if "x-frame-options" not in keys_lower:
                hints.append("Missing X-Frame-Options (clickjacking protection).")
            if "x-content-type-options" not in keys_lower:
                hints.append("Missing X-Content-Type-Options (MIME sniffing protection).")

            # Very simple 'risk level' based on hints count
            if len(hints) == 0:
                risk = "Low"
            elif len(hints) <= 2:
                risk = "Medium"
            else:
                risk = "High"

            # Run extra tasks in parallel: ports + robots.txt
            ports_result, robots_info = await asyncio.gather(
                scan_common_ports(host),
                fetch_robots(client, parsed.scheme, host),
            )

            return {
                "target": url,
                "final_url": final_url,
                "scheme": parsed.scheme or ("https" if is_https else "http"),
                "host": host,
                "ip": ip_address,
                "reverse_dns": rdns_name,
                "status_code": status_code,
                "status_family": status_family,
                "response_time_ms": duration_ms,
                "redirect_count": redirect_count,
                "content_length": content_length,
                "title": title,
                "interesting_headers": interesting,
                "hints": hints,
                "risk": risk,
                "ports": ports_result,
                "robots": robots_info,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            }

    except Exception as e:
        return {
            "target": url,
            "host": host,
            "ip": ip_address,
            "error": str(e),
        }
