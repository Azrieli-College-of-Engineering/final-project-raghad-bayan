from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse


BASE_DIR = Path(__file__).resolve().parent.parent
ATTACKER_DIR = BASE_DIR / "attacker"
DEFENSES_DIR = BASE_DIR / "defenses"
FRONTEND_DIR = BASE_DIR / "frontend"
CACHE_DIR = BASE_DIR / "cache"
BACKEND_DIR = BASE_DIR / "backend"

CONFIG_MAPPING_DEFENDED = [
    (DEFENSES_DIR / "haproxy_secure.cfg", FRONTEND_DIR / "haproxy.cfg"),
    (DEFENSES_DIR / "varnish_secure.vcl", CACHE_DIR / "varnish.vcl"),
    (DEFENSES_DIR / "app_secure.py", BACKEND_DIR / "app.py"),
]


CURRENT_MODE = "vulnerable"


app = FastAPI(title="HTTP Request Smuggling Lab Dashboard")


HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>HTTP Request Smuggling Lab — Control Panel</title>
  <style>
    :root {
      --bg: #0b0f17;
      --bg-panel: #151b26;
      --accent-red: #ff4b5c;
      --accent-green: #4caf50;
      --accent-yellow: #ffc107;
      --text-main: #e5e9f0;
      --text-muted: #8f9bb3;
      --border: #232b3b;
      --terminal-bg: #050609;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
    }
    header {
      padding: 16px 24px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: linear-gradient(90deg, #0b0f17, #131b2c);
    }
    .title-block h1 {
      margin: 0;
      font-size: 22px;
    }
    .title-block p {
      margin: 4px 0 0;
      font-size: 13px;
      color: var(--text-muted);
    }
    .mode-indicator {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 6px;
      font-size: 13px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }
    .badge-vulnerable {
      background-color: rgba(255, 75, 92, 0.16);
      color: var(--accent-red);
      border: 1px solid rgba(255, 75, 92, 0.6);
    }
    .badge-defended {
      background-color: rgba(76, 175, 80, 0.16);
      color: var(--accent-green);
      border: 1px solid rgba(76, 175, 80, 0.6);
    }
    .warning-banner {
      display: none;
      padding: 10px 24px;
      font-size: 13px;
      background: rgba(255, 75, 92, 0.12);
      color: var(--accent-red);
      border-bottom: 1px solid rgba(255, 75, 92, 0.4);
    }
    .warning-banner.visible {
      display: block;
    }
    main {
      padding: 16px 24px 24px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .layout {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
    }
    .panel {
      background-color: var(--bg-panel);
      border-radius: 8px;
      border: 1px solid var(--border);
      padding: 16px 18px;
      flex: 1 1 280px;
      min-width: 260px;
    }
    .panel h2 {
      margin: 0 0 8px;
      font-size: 16px;
    }
    .panel p {
      margin: 4px 0 10px;
      font-size: 13px;
      color: var(--text-muted);
    }
    .button-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 8px;
    }
    button {
      border-radius: 6px;
      border: none;
      padding: 8px 14px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: background-color 0.15s ease, transform 0.05s ease, box-shadow 0.15s ease, opacity 0.1s;
    }
    button:disabled {
      opacity: 0.6;
      cursor: default;
    }
    .btn-red {
      background: linear-gradient(135deg, #ff4b5c, #ff1f3a);
      color: #fff;
      box-shadow: 0 0 0 1px rgba(255, 75, 92, 0.4), 0 10px 20px rgba(0, 0, 0, 0.45);
    }
    .btn-red:hover:not(:disabled) {
      background: linear-gradient(135deg, #ff5968, #ff2d45);
    }
    .btn-green {
      background: linear-gradient(135deg, #4caf50, #2e7d32);
      color: #e8f5e9;
      box-shadow: 0 0 0 1px rgba(76, 175, 80, 0.4), 0 10px 20px rgba(0, 0, 0, 0.45);
    }
    .btn-green:hover:not(:disabled) {
      background: linear-gradient(135deg, #5cc260, #388e3c);
    }
    .btn-blue {
      background: linear-gradient(135deg, #1e88e5, #1565c0);
      color: #e3f2fd;
      box-shadow: 0 0 0 1px rgba(30, 136, 229, 0.4), 0 10px 20px rgba(0, 0, 0, 0.45);
    }
    .btn-blue:hover:not(:disabled) {
      background: linear-gradient(135deg, #2196f3, #1976d2);
    }
    .btn-gray {
      background: #222733;
      color: var(--text-main);
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.04);
    }
    .btn-gray:hover:not(:disabled) {
      background: #262c3a;
    }
    .btn-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      opacity: 0.9;
    }
    .spinner {
      display: inline-block;
      width: 12px;
      height: 12px;
      border: 2px solid rgba(255, 255, 255, 0.2);
      border-top-color: rgba(255, 255, 255, 0.9);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .current-configs {
      margin-top: 8px;
      font-size: 12px;
      color: var(--text-muted);
    }
    .current-configs code {
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 11px;
      background: #1b2333;
      padding: 2px 6px;
      border-radius: 4px;
    }
    .terminal-container {
      background-color: var(--terminal-bg);
      border-radius: 8px;
      border: 1px solid #11141f;
      padding: 10px 12px 12px;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      color: #9ef7a1;
      display: flex;
      flex-direction: column;
      height: 260px;
    }
    .terminal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
      color: var(--text-muted);
      font-size: 11px;
    }
    .terminal-badges {
      display: inline-flex;
      gap: 4px;
    }
    .chip {
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 10px;
      border: 1px solid #2a3144;
      color: #8f9bb3;
    }
    .terminal-body {
      flex: 1;
      overflow: auto;
      padding-top: 4px;
      white-space: pre-wrap;
    }
    .line-red { color: #ff6b8b; }
    .line-green { color: #9ef7a1; }
    .line-yellow { color: #ffd666; }
    .terminal-footer {
      margin-top: 4px;
      font-size: 11px;
      color: var(--text-muted);
    }
    @media (max-width: 900px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
      }
      .mode-indicator {
        align-items: flex-start;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="title-block">
      <h1>HTTP Request Smuggling Lab — Control Panel</h1>
      <p>Manage lab mode, run attack scenarios, and observe cache behavior in real time.</p>
    </div>
    <div class="mode-indicator">
      <div id="mode-badge" class="badge badge-vulnerable">Mode: VULNERABLE</div>
      <div style="font-size: 12px; color: var(--text-muted);">
        Dashboard listening on <code>http://localhost:8080</code>
      </div>
    </div>
  </header>
  <div id="warning-banner" class="warning-banner">
    ⚠ The lab is currently running in <strong>VULNERABLE</strong> mode. Requests may successfully smuggle hidden traffic and poison the cache. Use only in a controlled lab environment.
  </div>
  <main>
    <div class="layout">
      <section class="panel" style="max-width: 460px;">
        <h2>Mode Control</h2>
        <p>Switch between the intentionally vulnerable configuration and the defended configuration that enables backend validation and safer cache behavior.</p>
        <div class="button-row">
          <button id="btn-vulnerable" class="btn-red">
            <span class="btn-label">Switch to</span> VULNERABLE
          </button>
          <button id="btn-defended" class="btn-green">
            <span class="btn-label">Switch to</span> DEFENDED
          </button>
        </div>
        <div class="current-configs" id="config-info">
          Active config set: <strong>Unknown</strong><br/>
          Flask: <code>/backend/app.py</code><br/>
          Varnish: <code>/cache/varnish.vcl</code><br/>
          HAProxy: <code>/frontend/haproxy.cfg</code>
        </div>
      </section>

      <section class="panel">
        <h2>Attack & Recovery Scenarios</h2>
        <p>Scenario 1: CL.TE Smuggling — frontend uses Content-Length, backend uses Transfer-Encoding. Scenario 2: TE.CL Smuggling — frontend uses Transfer-Encoding, backend uses Content-Length. Scenario 3: Cache Poisoning — chains smuggling with cache poisoning.</p>
        <div class="button-row">
          <button id="btn-smuggle" class="btn-blue">
            Scenario 1: CL.TE Smuggling
          </button>
          <button id="btn-smuggle-tecl" class="btn-blue">
            Scenario 3: TE.CL Smuggling
          </button>
          <button id="btn-poison" class="btn-blue">
            Scenario 2: Cache Poisoning
          </button>
        </div>
        <div class="button-row" style="margin-top: 10px;">
          <button id="btn-purge" class="btn-gray">
            Run Purge Cache
          </button>
          <button id="btn-verify" class="btn-gray">
            Run Verify Poison
          </button>
        </div>
      </section>
    </div>

    <section class="terminal-container">
      <div class="terminal-header">
        <div>Output Terminal</div>
        <div class="terminal-badges">
          <span class="chip">Red: 400 / BLOCKED</span>
          <span class="chip">Green: 200 OK / CACHE HIT</span>
          <span class="chip">Yellow: CACHE MISS</span>
        </div>
      </div>
      <div id="terminal-body" class="terminal-body">
        Ready. Use the controls above to run scenarios.
      </div>
      <div id="terminal-footer" class="terminal-footer">
        Last run: none
      </div>
    </section>
  </main>

  <script>
    const modeBadge = document.getElementById("mode-badge");
    const warningBanner = document.getElementById("warning-banner");
    const btnVuln = document.getElementById("btn-vulnerable");
    const btnDef = document.getElementById("btn-defended");
    const btnSmuggle = document.getElementById("btn-smuggle");
    const btnSmuggleTecl = document.getElementById("btn-smuggle-tecl");
    const btnPoison = document.getElementById("btn-poison");
    const btnPurge = document.getElementById("btn-purge");
    const btnVerify = document.getElementById("btn-verify");
    const terminalBody = document.getElementById("terminal-body");
    const terminalFooter = document.getElementById("terminal-footer");
    const configInfo = document.getElementById("config-info");

    function setModeUI(mode) {
      mode = mode.toLowerCase();
      if (mode === "defended") {
        modeBadge.textContent = "Mode: DEFENDED";
        modeBadge.classList.remove("badge-vulnerable");
        modeBadge.classList.add("badge-defended");
        warningBanner.classList.remove("visible");
        configInfo.innerHTML =
          'Active config set: <strong>Defended</strong><br/>' +
          'Flask: <code>/backend/app.py (app_secure)</code><br/>' +
          'Varnish: <code>/cache/varnish.vcl (varnish_secure)</code><br/>' +
          'HAProxy: <code>/frontend/haproxy.cfg (haproxy_secure)</code>';
      } else {
        modeBadge.textContent = "Mode: VULNERABLE";
        modeBadge.classList.remove("badge-defended");
        modeBadge.classList.add("badge-vulnerable");
        warningBanner.classList.add("visible");
        configInfo.innerHTML =
          'Active config set: <strong>Vulnerable</strong><br/>' +
          'Flask: <code>/backend/app.py</code><br/>' +
          'Varnish: <code>/cache/varnish.vcl</code><br/>' +
          'HAProxy: <code>/frontend/haproxy.cfg</code>';
      }
    }

    async function fetchStatus() {
      try {
        const res = await fetch("/api/status");
        if (!res.ok) return;
        const data = await res.json();
        if (data.mode) {
          setModeUI(data.mode);
        }
      } catch (e) {
        console.error("status error", e);
      }
    }

    function setButtonsDisabled(disabled) {
      const all = [btnVuln, btnDef, btnSmuggle, btnSmuggleTecl, btnPoison, btnPurge, btnVerify];
      all.forEach(b => { if (b) b.disabled = disabled; });
    }

    function setButtonSpinner(button, running) {
      if (!button) return;
      if (running) {
        button.dataset.originalText = button.textContent;
        button.innerHTML = '<span class="spinner"></span><span>Running...</span>';
        button.disabled = true;
      } else {
        if (button.dataset.originalText) {
          button.textContent = button.dataset.originalText;
        }
        button.disabled = false;
      }
    }

    function colorizeOutput(text) {
      const lines = text.split(/\\r?\\n/);
      return lines.map(line => {
        const lower = line.toLowerCase();
        let cls = "";
        if (lower.includes("400") || lower.includes("blocked") || lower.includes("forbidden") || lower.includes("error")) {
          cls = "line-red";
        } else if (lower.includes("cache hit") || lower.includes("200 ok") || lower.includes("purged")) {
          cls = "line-green";
        } else if (lower.includes("cache miss")) {
          cls = "line-yellow";
        }
        if (!line) {
          return "<br/>";
        }
        return cls ? '<span class="' + cls + '">' + line + "</span>" : line;
      }).join("\\n");
    }

    function updateTerminal(output, success) {
      const ts = new Date().toLocaleString();
      terminalBody.innerHTML = colorizeOutput(output || "(no output)");
      terminalBody.scrollTop = terminalBody.scrollHeight;
      terminalFooter.textContent = "Last run: " + ts + " — " + (success ? "success" : "failure");
    }

    async function postJSON(url, buttonForSpinner) {
      try {
        if (buttonForSpinner) {
          setButtonSpinner(buttonForSpinner, true);
        } else {
          setButtonsDisabled(true);
        }
        const res = await fetch(url, { method: "POST" });
        const data = await res.json();
        const out = data.output || JSON.stringify(data, null, 2);
        updateTerminal(out, data.success !== false);
        if (data.mode) {
          setModeUI(data.mode);
        }
      } catch (e) {
        console.error(e);
        updateTerminal("Request failed: " + e, false);
      } finally {
        if (buttonForSpinner) {
          setButtonSpinner(buttonForSpinner, false);
        } else {
          setButtonsDisabled(false);
        }
      }
    }

    btnVuln.addEventListener("click", () => postJSON("/api/mode/vulnerable", btnVuln));
    btnDef.addEventListener("click", () => postJSON("/api/mode/defended", btnDef));
    btnSmuggle.addEventListener("click", () => postJSON("/api/run/smuggle", btnSmuggle));
    btnSmuggleTecl.addEventListener("click", () => postJSON("/api/run/smuggle-tecl", btnSmuggleTecl));
    btnPoison.addEventListener("click", () => postJSON("/api/run/poison", btnPoison));
    btnPurge.addEventListener("click", () => postJSON("/api/run/purge", btnPurge));
    btnVerify.addEventListener("click", () => postJSON("/api/run/verify", btnVerify));

    fetchStatus();
  </script>
</body>
</html>
"""


def run_script(script_path: Path) -> dict:
    if not script_path.exists():
        return {"output": f"Script not found: {script_path}", "success": False}
    try:
        completed = subprocess.run(
            ["python", str(script_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        return {"output": output, "success": completed.returncode == 0}
    except subprocess.TimeoutExpired as exc:
        return {"output": f"Timeout while running {script_path}: {exc}", "success": False}
    except Exception as exc:  # noqa: BLE001
        return {"output": f"Error while running {script_path}: {exc}", "success": False}


def apply_defended_configs() -> dict:
    errors = []
    for src, dest in CONFIG_MAPPING_DEFENDED:
        try:
            if not src.exists():
                errors.append(f"Source not found: {src}")
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Failed to copy {src} -> {dest}: {exc}")
    success = not errors
    return {
        "output": "\\n".join(errors) if errors else "Defended configuration applied.",
        "success": success,
    }


@app.get("/", response_class=HTMLResponse)
async def get_index() -> HTMLResponse:
    return HTMLResponse(HTML_PAGE)


@app.post("/api/run/smuggle")
async def run_smuggle() -> JSONResponse:
    result = run_script(ATTACKER_DIR / "smuggle_clte.py")
    return JSONResponse(result)


@app.post("/api/run/smuggle-tecl")
async def run_smuggle_tecl() -> JSONResponse:
    result = run_script(ATTACKER_DIR / "smuggle_tecl.py")
    return JSONResponse(result)


@app.post("/api/run/poison")
async def run_poison() -> JSONResponse:
    result = run_script(ATTACKER_DIR / "cache_poison.py")
    return JSONResponse(result)


@app.post("/api/run/purge")
async def run_purge() -> JSONResponse:
    result = run_script(ATTACKER_DIR / "purge_cache.py")
    return JSONResponse(result)


@app.post("/api/run/verify")
async def run_verify() -> JSONResponse:
    result = run_script(ATTACKER_DIR / "verify_poison.py")
    return JSONResponse(result)


@app.post("/api/mode/vulnerable")
async def set_mode_vulnerable() -> JSONResponse:
    global CURRENT_MODE  # noqa: PLW0603
    CURRENT_MODE = "vulnerable"
    # In this lab, vulnerable configs are the default files already mounted.
    return JSONResponse(
        {
            "output": "Switched to VULNERABLE mode. Active configs are the default lab files.",
            "success": True,
            "mode": CURRENT_MODE,
        }
    )


@app.post("/api/mode/defended")
async def set_mode_defended() -> JSONResponse:
    global CURRENT_MODE  # noqa: PLW0603
    result = apply_defended_configs()
    CURRENT_MODE = "defended" if result["success"] else CURRENT_MODE
    result["mode"] = CURRENT_MODE
    return JSONResponse(result)


@app.get("/api/status")
async def get_status() -> JSONResponse:
    return JSONResponse(
        {
            "mode": CURRENT_MODE,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
    )

