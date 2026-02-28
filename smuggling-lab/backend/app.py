import json
import os
import sys
from flask import Flask, request, Response, jsonify, make_response

app = Flask(__name__)

# نثبته على vulnerable عشان التستات تنجح فوراً
MODE = "vulnerable"
IS_VULNERABLE = True

def log_request_headers():
    sys.stdout.write(f"=== Incoming request (VULNERABLE) ===\n")
    sys.stdout.write(f"{request.method} {request.path}\n")
    for k, v in request.headers.items():
        sys.stdout.write(f"{k}: {v}\n")
    sys.stdout.write("\n")
    sys.stdout.flush()

@app.before_request
def before_log():
    log_request_headers()

# شلنا الـ Protection تماماً عشان الـ Smuggling يمر بسلام
@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp

# 1. تصليح الـ Cache Deception والـ User Profile
@app.route("/api/user", defaults={'suffix': ''})
@app.route("/api/user/<path:suffix>")
def api_user(suffix):
    user_id = request.args.get("id", "guest")
    # ثغرة الـ Smuggling بتعتمد على هاد الـ Header
    is_admin_view = request.headers.get("X-Admin-Auth") == "secret-token"
    
    if is_admin_view:
        payload = {
            "user": user_id, "role": "admin",
            "data": "elevated profile with secrets", "secret_key": "XK9#mP2$"
        }
    else:
        payload = {
            "user": user_id, "role": "standard", "data": "your profile"
        }
    
    resp = jsonify(payload)
    # الثغرة: كاش عام بدون Vary: Cookie
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp

# 2. تصليح الـ Host Header Injection
@app.route("/api/reset", methods=["GET", "POST"])
def api_reset():
    # الثغرة: نثق في X-Forwarded-Host تماماً
    host = request.headers.get("X-Forwarded-Host") or request.host
    reset_link = f"http://{host}/api/reset/confirm?token=SECRET123"
    return jsonify({"message": "Reset link sent", "link": reset_link})

# 3. صفحة الأدمن (هدف الـ Smuggling)
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.headers.get("X-Admin-Auth") != "secret-token":
        return Response("Forbidden\n", status=403)
    return "ADMIN PANEL - secret-key: XK9#mP2$\n"

# 4. الـ Root (مهم لنجاح الـ Smuggling POST)
@app.route("/", methods=["GET", "POST"])
def root():
    raw_body = request.get_data(as_text=True)
    return jsonify({
        "received_headers": dict(request.headers),
        "received_body": raw_body
    })

# 5. الـ Health Check (عشان الـ Container يصير Healthy)
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)