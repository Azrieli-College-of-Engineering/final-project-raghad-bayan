import argparse
import socket

TARGET_HOST = "localhost"
TARGET_PORT = 80


def send(raw):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.sendall(raw.encode("ascii"))
    data = s.recv(65535)
    s.close()
    return data.decode("iso-8859-1", errors="replace")


def print_cache_status(resp_text, idx):
    headers, _, body = resp_text.partition("\r\n\r\n")
    age = ""
    x_varnish = ""
    for line in headers.split("\r\n"):
        if line.lower().startswith("age:"):
            age = line
        if line.lower().startswith("x-varnish:"):
            x_varnish = line
    poisoned = "admin" in body or "secret_key" in body
    state = "POISONED" if poisoned else "CLEAN"
    print(f"\n[# {idx}] Cache state guess: {state}")
    if age:
        print(f"    {age}")
    if x_varnish:
        print(f"    {x_varnish}")
    print("    Body preview:", body[:200].replace("\n", " "))


def main():
    parser = argparse.ArgumentParser(description="Verify Varnish cache state for /api/user")
    parser.add_argument(
        "--bust",
        action="store_true",
        help="Send a cache-busting request first to try to reset cache",
    )
    args = parser.parse_args()

    if args.bust:
        print("Sending cache-busting request: GET /api/user?id=bust123")
        bust_req = (
            "GET /api/user?id=bust123 HTTP/1.1\r\n"
            f"Host: {TARGET_HOST}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        resp = send(bust_req)
        print(resp)

    print("\nRequesting /api/user 5 times to inspect cache behavior.")
    req = (
        "GET /api/user HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    for i in range(1, 6):
        resp = send(req)
        print_cache_status(resp, i)


if __name__ == "__main__":
    main()

