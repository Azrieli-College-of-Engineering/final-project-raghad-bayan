import json
import sys
from flask import Flask, request, Response, jsonify

app = Flask(__name__)


def log_request_headers():
    sys.stdout.write("=== Incoming request ===\n")
    sys.stdout.write(f"{request.method} {request.path}?{request.query_string.decode()}\n")
    for k, v in request.headers.items():
        sys.stdout.write(f"{k}: {v}\n")
    sys.stdout.write("\n")
    sys.stdout.flush()


@app.before_request
def before_request():
    log_request_headers()


@app.route("/api/user")
def api_user():
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
def admin():
    token = request.headers.get("X-Admin-Auth")
    if token != "secret-token":
        return Response("Forbidden\n", status=403, headers={"Cache-Control": "no-store"})
    body = "ADMIN PANEL - user list: alice, bob, charlie, secret-key: XK9#mP2$\n"
    return Response(body, status=200, headers={"Cache-Control": "no-store"})


@app.route("/api/health")
def api_health():
    resp = jsonify({"status": "ok", "server": "backend"})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/", methods=["POST"])
def root_post():
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
def api_public():
    payload = {"message": "this is public content", "version": "1.0"}
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
