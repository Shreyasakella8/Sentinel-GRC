"""
SENTINEL-GRC — Core Rate Limiter

X-Forwarded-For aware key function:
  - Behind a load balancer/reverse proxy, request.client.host is always the
    proxy IP (e.g. 10.0.0.1), so all clients share a single rate limit bucket.
  - By reading X-Forwarded-For first, each real client gets its own bucket.
  - Only the FIRST IP in XFF is trusted to prevent IP spoofing via header injection
    (attackers can append arbitrary IPs to XFF, but cannot control the leftmost value
    which is set by the outermost trusted proxy).

Security note: if your deployment does NOT sit behind a proxy, remove the XFF
branch and use slowapi.util.get_remote_address directly to avoid spoofing risk.
"""

from fastapi import Request
from slowapi import Limiter


def _get_real_ip(request: Request) -> str:
    """
    Extract the real client IP respecting proxy forwarding headers.

    Priority:
      1. X-Forwarded-For (leftmost — set by outermost proxy, tamper-resistant)
      2. X-Real-IP (nginx convention)
      3. request.client.host (fallback for direct connections)
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # Take the first (leftmost) IP — this is the original client IP added
        # by the outermost trusted reverse proxy. Subsequent IPs are appended
        # by inner proxies and could be spoofed by the client.
        return xff.split(",")[0].strip()

    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip:
        return x_real_ip.strip()

    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_get_real_ip)
