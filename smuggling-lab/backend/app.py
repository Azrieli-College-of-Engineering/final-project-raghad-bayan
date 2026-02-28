import json
import os
import sys
from flask import Flask, request, Response, jsonify, make_response

app = Flask(__name__)

# تأكد إن MODE مساوي لـ vulnerable عشان تنجح التستات
MODE = os.environ.get("MODE", "vulnerable").lower() 
IS_VULNERABLE = MODE == "vulnerable"

def log_request_headers():
    mode_label = "vulnerable app" if IS_VULNERABLE else "secure app"
    sys.stdout.write(f"=== Incoming request ({mode_label}) ===\n")
    sys.stdout.write(f"{request.method} {request.path}?{request.query_string.decode()}\n")
    for k, v in request.headers.items():
        sys.stdout.write(f"{k}: {v}\n")
    sys.stdout.write("\n")
    sys.stdout.flush()

@app.before_request
def before_log():
    log_request_headers()

@app.before_request
def maybe_block_smuggling():
    if IS_VULNERABLE:
        # في حالة الـ Vulnerable، بنسمح بكل شي عشان الـ Smuggling يمر
        return None

    te = request.headers.get("Transfer-Encoding", "")
    if "chunked" in te.lower():
        return make_response("400 Bad Request - Smuggling Blocked", 400)

    has_cl = "Content-Length" in request.headers
    has_te = "Transfer-Encoding" in request.headers
    if has_cl and has_te:
        return make_response("400 Bad Request - Ambiguous framing", 400)

@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp

# ── التعديل 1: دعم الـ Cache Deception ────────────────────────────────────────
# السكربت بيبعث لـ /api/user/profile.css ، لازم نقبل الـ GET والـ Suffix
@app.route("/api/user", defaults={'suffix': ''})
@app.route("/api/user/<path:suffix>")
def api_user(suffix):
    # إذا فيه suffix والمود مش vulnerable، بنرجع 404 (حماية)
    if suffix and not IS_VULNERABLE:
        return make_response(jsonify({"error": "Not found"}), 404)

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
    # الثغرة: ما فيه Vary: Cookie، والـ Cache-Control عام (Public)
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp

# ── التعديل 2: دعم الـ Host Header Injection ──────────────────────────────────
# السكربت بيجرب GET و POST، رح نخليه يقبل الاثنين عشان نتفادى 405
@app.route("/api/reset", methods=["GET", "POST"])
def api_reset():
    if IS_VULNERABLE:
        # الثغرة: استخدام X-Forwarded-Host لبناء الرابط
        host = request.headers.get("X-Forwarded-Host") or request.host
    else:
        host = "safe.domain.com"

    reset_link = f"http://{host}/api/reset/confirm?token=SECRET123"
    
    return jsonify({
        "message": "Reset link generated",
        "link": reset_link
    })

@app.route("/admin", methods=["GET", "POST"])
def admin():
    token = request.headers.get("X-Admin-Auth")
    if token != "secret-token":
        return Response("Forbidden\n", status=403)
    return "ADMIN PANEL - secret-key: XK9#mP2$\n"

@app.route("/", methods=["GET", "POST"])
def root():
    # تعديل: قبول GET و POST عشان الـ Smuggling أحياناً بيبعث طلبات فارغة للـ Root
    raw_body = request.get_data(as_text=True)
    return jsonify({
        "received_headers": dict(request.headers),
        "received_body": raw_body
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)