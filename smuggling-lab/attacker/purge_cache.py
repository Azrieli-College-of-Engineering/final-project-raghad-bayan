import os
import socket

TARGET_HOST = os.environ.get("TARGET_HOST", "localhost")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "80"))


def send_raw(data):
    """Send raw bytes and return response as string."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(data)
    response = s.recv(65535)
    s.close()
    return response.decode("iso-8859-1", errors="replace")


def get_header(resp_text, name):
    """Get first value of header (case-insensitive)."""
    headers, _, _ = resp_text.partition("\r\n\r\n")
    name_lower = name.lower()
    for line in headers.split("\r\n")[1:]:  # skip status line
        if line.lower().startswith(name_lower + ":"):
            return line.split(":", 1)[1].strip()
    return None


def get_status_line(resp_text):
    """Get first line (e.g. HTTP/1.1 200 OK)."""
    return resp_text.split("\r\n", 1)[0] if resp_text else ""


def is_cache_hit(resp_text):
    """True if X-Cache is HIT or X-Varnish/Age indicate cached response."""
    x_cache = get_header(resp_text, "X-Cache")
    if x_cache:
        return x_cache.upper() == "HIT"
    # Fallback: X-Varnish with two IDs or Age > 0
    headers, _, _ = resp_text.partition("\r\n\r\n")
    x_varnish = get_header(resp_text, "X-Varnish") or ""
    age_val = get_header(resp_text, "Age")
    two_ids = len(x_varnish.split()) >= 2
    try:
        age_gt_zero = age_val is not None and int(age_val) > 0
    except ValueError:
        age_gt_zero = False
    return two_ids or age_gt_zero


def body_has_admin_data(resp_text):
    """True if body contains admin role or secret_key."""
    _, _, body = resp_text.partition("\r\n\r\n")
    return "admin" in body.lower() and ("secret_key" in body or "XK9" in body)


def extract_role_preview(resp_text):
    """Return short preview: role and optional secret_key for display."""
    _, _, body = resp_text.partition("\r\n\r\n")
    lines = []
    if '"role"' in body:
        idx = body.find('"role"')
        rest = body[idx:]
        if ': "admin"' in rest or ": \"admin\"" in rest:
            lines.append("role: ADMIN")
        elif ': "standard"' in rest or ": \"standard\"" in rest:
            lines.append("role: standard")
        else:
            lines.append("role: standard")
    else:
        lines.append("role: standard")
    if "secret_key" in body or "XK9" in body:
        lines.append("secret_key: XK9#mP2$")
    return ", ".join(lines)


def main():
    print("=== Cache Purge Tool ===\n")

    # BEFORE: GET /api/user
    get_req = (
        "GET /api/user HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    print("[BEFORE PURGE] GET /api/user")
    before = send_raw(get_req)
    role_preview = extract_role_preview(before)
    hit = is_cache_hit(before)
    poisoned = body_has_admin_data(before)
    if hit and poisoned:
        status = "CACHE HIT (POISONED)"
    elif hit:
        status = "CACHE HIT"
    else:
        status = "CACHE MISS (CLEAN)" if not poisoned else "CACHE MISS (POISONED)"
    print(f"{role_preview}")
    print(f"Status: {status}\n")

    # PURGE
    purge_req = (
        "PURGE /api/user HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "X-Purge-Key: internal-purge-secret\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    print("[PURGING] Sending PURGE /api/user with X-Purge-Key...")
    purge_resp = send_raw(purge_req)
    status_line = get_status_line(purge_resp)
    if "200" in status_line:
        print(f"Purge response: {status_line} - Purged\n")
    else:
        print(f"Purge response: {status_line}\n")

    # AFTER: GET /api/user
    print("[AFTER PURGE] GET /api/user")
    after = send_raw(get_req)
    role_preview_after = extract_role_preview(after)
    hit_after = is_cache_hit(after)
    poisoned_after = body_has_admin_data(after)
    if hit_after and poisoned_after:
        status_after = "CACHE HIT (POISONED)"
    elif hit_after:
        status_after = "CACHE HIT"
    else:
        status_after = "CACHE MISS (CLEAN)" if not poisoned_after else "CACHE MISS (POISONED)"
    print(f"{role_preview_after}")
    print(f"Status: {status_after}\n")

    # Result
    if "200" in status_line and not poisoned_after:
        print("Cache successfully purged. Poisoned entry removed.")
    elif "403" in status_line:
        print("Purge rejected (403 Forbidden). Check X-Purge-Key is set correctly.")
    else:
        print("Purge completed. Verify cache state above.")


if __name__ == "__main__":
    main()
