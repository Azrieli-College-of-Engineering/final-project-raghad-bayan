import json
import sys
from flask import Flask, request, Response, jsonify, make_response

app = Flask(__name__)


def log_request_headers():
    sys.stdout.write("=== Incoming request (secure app) ===\n")
    sys.stdout.write(f"{request.method} {request.path}?{request.query_string.decode()}\n")
    for k, v in request.headers.items():
        sys.stdout.write(f"{k}: {v}\n")
    sys.stdout.write("\n")
    sys.stdout.flush()


@app.before_request
def block_ambiguous_framing():
    """
    Defense against HTTP Request Smuggling.
    Reject any request that contains Transfer-Encoding: chunked
    since legitimate requests through our proxy chain should never
    have this header reach the backend directly from clients.
    The proxy (HAProxy/Varnish) should handle chunked encoding.
    If TE: chunked reaches the backend, it indicates a smuggling attempt.
    """
    te = request.headers.get("Transfer-Encoding", "")
    if "chunked" in te.lower():
        app.logger.warning(f"BLOCKED: Smuggling attempt detected - Transfer-Encoding: {te}")
        return make_response(
            "400 Bad Request - Transfer-Encoding not permitted on this endpoint",
            400,
        )


@app.before_request
def block_ambiguous_framing_cl_te():
    """Defense-in-depth: reject requests with both Content-Length and Transfer-Encoding."""
    has_cl = "Content-Length" in request.headers
    has_te = "Transfer-Encoding" in request.headers
    if has_cl and has_te:
        return make_response("400 Bad Request - Ambiguous framing rejected", 400)


@app.before_request
def before_secure():
    log_request_headers()


@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


@app.route("/api/user")
def api_user_secure():
    user_id = request.args.get("id", "guest")
    is_admin_view = request.headers.get("X-Admin-Auth") == "secret-token"
    if is_admin_view:
        payload = {
            "user": user_id,
            "role": "admin",
            "data": "elevated profile with secrets",
            "secret_key": "XK9#mP2$",
        }
    else:
        payload = {
            "user": user_id,
            "role": "standard",
            "data": "your profile",
        }

    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@app.route("/admin", methods=["GET", "POST"])
def admin_secure():
    token = request.headers.get("X-Admin-Auth")
    if token != "secret-token":
        return Response("Forbidden\n", status=403, headers={"Cache-Control": "no-store"})

    body = "ADMIN PANEL - user list: alice, bob, charlie, secret-key: XK9#mP2$\n"
    return Response(body, status=200, headers={"Cache-Control": "no-store"})


@app.route("/api/health")
def api_health_secure():
    resp = jsonify({"status": "ok", "server": "backend-secure"})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/", methods=["POST"])
def root_post_secure():
    raw_body = request.get_data(cache=False, as_text=True)
    headers_dict = {k: v for k, v in request.headers.items()}
    payload = {
        "received_headers": headers_dict,
        "received_body": raw_body,
    }
    resp = Response(json.dumps(payload, indent=2), mimetype="application/json")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/public")
def api_public_secure():
    payload = {"message": "this is public content", "version": "1.0"}
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

