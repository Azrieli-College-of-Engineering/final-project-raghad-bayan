## HTTP Request Smuggling + Cache Poisoning Lab

### Overview

This lab is an intentionally vulnerable three-tier web stack that demonstrates **HTTP/1.1 request smuggling** and **cache poisoning** using a classic **CL.TE desynchronization**:

- **CL (Content-Length) vs TE (Transfer-Encoding: chunked)** disagreement between layers
- A front-end proxy uses **Content-Length** to frame requests
- A back-end server uses **Transfer-Encoding: chunked** to frame requests
- The disagreement lets an attacker **smuggle a hidden HTTP request** that rides on a shared backend connection and can then **poison the cache** for all users

You get:

- A vulnerable stack using **HAProxy → Varnish → Flask**
- Raw-socket Python attack scripts
- Hardened configurations showing how to defend against the attack

---

### Architecture Diagram (ASCII)

```text
            Attacker / Victim Browser
                       |
                       v
                [ HAProxy 2.4 ]
                frontend (port 80)
                - HTTP/1.1 keep-alive
                - Forwards CL+TE intact
                       |
                       v
                [  Varnish 7  ]
                cache (port 6081)
                - Caches /api/* GET
                - Insecure hash (ignores Cookie/Auth, collapses /api/user)
                       |
                       v
             [ Flask Backend API ]
                 (port 5000)
              - Processes TE: chunked
              - /admin protected by header
              - /api/user and /api/public cacheable
```

External access is only to **HAProxy on port 80**; all other communication is on the internal Docker network.

---

### Project Structure

```text
smuggling-lab/
├── docker-compose.yml
├── frontend/
│   └── haproxy.cfg              # vulnerable HAProxy
├── cache/
│   └── varnish.vcl              # vulnerable Varnish config
├── backend/
│   ├── Dockerfile               # Flask backend built on python:3.11-slim
│   ├── requirements.txt         # flask==3.0.0
│   └── app.py                   # vulnerable Flask app
├── attacker/
│   ├── smuggle_clte.py          # Scenario 1: CL.TE request smuggling
│   ├── cache_poison.py          # Scenario 2: cache poisoning via smuggling
│   └── verify_poison.py         # Verify cache state and optional bust
├── defenses/
│   ├── haproxy_secure.cfg       # hardened HAProxy
│   ├── varnish_secure.vcl       # hardened Varnish
│   └── app_secure.py            # hardened Flask app
└── README.md
```

---

### Setup Instructions

From the repo root:

```bash
git clone <your-repo-url> smuggling-lab-repo
cd smuggling-lab-repo/smuggling-lab

# Build and start the vulnerable stack
docker-compose up --build
```

Services:

- **frontend**: HAProxy 2.4 on `localhost:80`
- **cache**: Varnish 7 on internal port `6081`
- **backend**: Flask app on internal port `5000`

Health dependencies:

- Backend starts first and exposes `/api/health`
- Varnish depends on backend
- HAProxy depends on Varnish

---

### Running the Attacks

All attacker scripts use **raw Python sockets** to send byte-precise HTTP/1.1 requests (`\r\n` line endings).

Make sure the stack is running:

```bash
cd smuggling-lab
docker-compose up --build
```

Open another terminal for attacks:

```bash
cd smuggling-lab/attacker
python smuggle_clte.py
python cache_poison.py
python verify_poison.py
```

#### Scenario 1 – CL.TE Request Smuggling (`smuggle_clte.py`)

```bash
cd smuggling-lab/attacker
python smuggle_clte.py
```

What it does:

1. **Builds a single POST** to `/` with both:
   - `Content-Length: <N>` (covers chunked body + smuggled GET)
   - `Transfer-Encoding: chunked`
2. **Chunked body** sent to backend:
   - `1\r\nX\r\n0\r\n\r\n`  → backend thinks body ends here
3. **Smuggled request** is appended after the terminating chunk:
   - `GET /admin HTTP/1.1\r\nHost: localhost\r\nX-Admin-Auth: secret-token\r\n\r\n`
4. HAProxy uses **Content-Length** and forwards everything as one POST body.
5. Backend uses **Transfer-Encoding** and stops at `0\r\n\r\n`, leaving `GET /admin` sitting in the TCP buffer.
6. Script then waits ~500ms and sends a new **GET /api/user?id=victim** on a fresh client connection.

Expected console output:

- Clearly labeled:
  - Response to smuggling POST
  - Response to victim GET
- The **second response** should contain:
  - `ADMIN PANEL - user list: alice, bob, charlie, secret-key: XK9#mP2$`

What to look for:

- In the backend container logs, you should see:
  - First: `POST /` with TE: chunked
  - Then: a `GET /admin` even though you never sent it directly from the victim

#### Scenario 2 – Cache Poisoning via Smuggling (`cache_poison.py`)

```bash
cd smuggling-lab/attacker
python cache_poison.py
```

The script runs **four steps**, all printed with labels and raw responses:

1. **STEP 1 – Verify clean cache**
   - Sends `GET /api/user?id=guest`
   - Backend returns JSON:
     - `{"user": "guest", "role": "standard", "data": "your profile"}`
   - Response has `Cache-Control: public, max-age=300`
   - The script prints:
     - Headers
     - Body preview
     - `CACHE HIT` / `CACHE MISS` based on `Age` / `X-Varnish`

2. **STEP 2 – Smuggling POST**
   - Sends a CL.TE **POST /** with:
     - Chunked body `1\r\nX\r\n0\r\n\r\n`
     - Followed by smuggled:
       - `GET /api/user?id=guest` with `X-Admin-Auth: secret-token`
   - Backend processes the chunked POST (ignoring smuggled bytes) and queues the privileged `GET /api/user`.

3. **STEP 3 – Trigger request**
   - Sends benign `GET /api/user` (no query string) on a new connection.
   - On the backend side:
     - The queued smuggled request `GET /api/user?id=guest` with header `X-Admin-Auth: secret-token` is processed.
     - `app.py` sees `X-Admin-Auth: secret-token` and returns **admin-flavoured JSON**:
       - `role: "admin"`, plus `secret_key: "XK9#mP2$"`.
   - Varnish caches this response under the **collapsed key `/api/user`** (query string ignored in `vcl_hash`).

4. **STEP 4 – Verify poisoning**
   - Sends 3 more `GET /api/user` requests on separate connections.
   - All are served from cache and contain the **admin data**.
   - The script prints `CACHE HIT` / `CACHE MISS` for each based on:
     - `Age:` header
     - `X-Varnish:` header

What to look for:

- STEP 1 body: `"role": "standard"`
- STEP 3 and STEP 4 bodies: `"role": "admin"` and `"secret_key": "XK9#mP2$"`
- Increasing `Age` header values on later responses, confirming they are **served from Varnish cache**.

#### Scenario 2 – Verifying Cache State (`verify_poison.py`)

```bash
cd smuggling-lab/attacker
python verify_poison.py
```

Behavior:

1. Sends **5 sequential `GET /api/user` requests** to HAProxy.
2. For each response, prints:
   - Body preview
   - `Age` and `X-Varnish` response headers (if present)
   - A heuristic verdict: `POISONED` if body looks admin-like (e.g. contains `admin` or `secret_key`), otherwise `CLEAN`.

Optional cache-busting:

```bash
python verify_poison.py --bust
```

- First sends `GET /api/user?id=bust123` to change what backend might cache.
- Then performs the 5 standard `GET /api/user` runs again.

---

### Applying the Defenses

The `defenses/` directory contains hardened configs that neutralize the smuggling and cache-poisoning vectors.

#### 1. Harden HAProxy

- Vulnerable config: `frontend/haproxy.cfg`
- Secure config: `defenses/haproxy_secure.cfg`

Replace the mounted file in `docker-compose.yml` (or copy over the config):

```bash
cd smuggling-lab
cp defenses/haproxy_secure.cfg frontend/haproxy.cfg
docker-compose restart frontend
```

What changes:

- Rejects any request with **both `Content-Length` and `Transfer-Encoding`**:
  - Uses an ACL and `http-request deny` to return `400` with a clear message.
- Uses `http-server-close`:
  - Disables backend connection reuse, making it much harder to smuggle extra bytes across requests.

Re-run `smuggle_clte.py` / `cache_poison.py`:

- The smuggling POST should now be **rejected with 400**.
- No hidden `GET /admin` or privileged `GET /api/user` should show in backend logs.

#### 2. Harden Varnish

- Vulnerable config: `cache/varnish.vcl`
- Secure config: `defenses/varnish_secure.vcl`

Swap the VCL:

```bash
cd smuggling-lab
cp defenses/varnish_secure.vcl cache/varnish.vcl
docker-compose restart cache
```

What changes:

- Includes `Cookie` and `Authorization` in the **hash key**:
  - Prevents cache key confusion between authenticated and unauthenticated views.
- Never caches responses with `Set-Cookie`.
- Never caches POST responses.
- Adds `Vary: Cookie` on delivery:
  - Makes it explicit that the cache key varies with cookies.

Re-run `cache_poison.py`:

- Even if smuggling were still possible, Varnish will **not serve admin data to other users** under the same cache key.

#### 3. Harden the Flask App

- Vulnerable app: `backend/app.py`
- Secure app: `defenses/app_secure.py`

To use the secure app in Docker:

```bash
cd smuggling-lab
cp defenses/app_secure.py backend/app.py
docker-compose up --build
```

What changes:

- `before_request` hook that **rejects any request with both `Content-Length` and `Transfer-Encoding`** with `400 Bad Request`.
- Adds security headers to all responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
- Keeps the same endpoints and behavior but enforces stricter input validation.

Re-run `smuggle_clte.py`:

- Backend will refuse the smuggling POST, breaking the CL.TE discrepancy.

---

### How the Vulnerability Works

#### CL.TE Desync Mechanics (Byte-Level)

Consider the smuggling request built by `smuggle_clte.py`:

```http
POST / HTTP/1.1
Host: localhost
Connection: keep-alive
Content-Length: <N>
Transfer-Encoding: chunked

1\r\n
X\r\n
0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
X-Admin-Auth: secret-token\r\n
\r\n
```

Two different parsers see this differently:

- **Front-end (HAProxy)**
  - Uses `Content-Length: N` to decide how many bytes belong to this POST.
  - Treats everything after the header block (including `GET /admin ...`) as part of the body.
  - When N bytes arrive, HAProxy believes the POST is complete.

- **Back-end (Flask / Werkzeug)**
  - Sees `Transfer-Encoding: chunked` and **ignores `Content-Length`**.
  - Parses chunks:
    - `1\r\nX\r\n` → reads 1 byte of data: `X`
    - `0\r\n\r\n` → chunk terminator; POST body ends here.
  - **Stops reading** the request body at this point.
  - The remaining bytes starting at `GET /admin ...` are left unread in the backend connection buffer.

When the next client request arrives:

- HAProxy / Varnish reuses the backend TCP connection (keep-alive).
- The first thing waiting in that connection buffer is:
  - `GET /admin HTTP/1.1\r\nHost: ...`
- This **smuggled request** is processed **before or instead of** the victim’s intended request.

#### Why Varnish Caches the Poisoned Response

1. The smuggled request is:
   - `GET /api/user?id=guest` with `X-Admin-Auth: secret-token`.
2. `backend/app.py` checks `X-Admin-Auth`:
   - If `secret-token`, it responds with **admin-flavoured** JSON (`role: "admin"`, `secret_key` included), but still cacheable:
   - `Cache-Control: public, max-age=300`.
3. Varnish’s vulnerable `vcl_hash`:
   - For `/api/user`, it **ignores query parameters** and uses a single key:
     - `/api/user`
   - It explicitly **does not hash in Cookie or Authorization**.
4. Thus, the admin response for `/api/user?id=guest` is cached as if it were just `/api/user` with no auth context.
5. Later, any user requesting `/api/user` (no query, no auth) gets served:
   - The **admin response** from cache.

#### Why All Subsequent Users Are Affected

- The poisoned object remains in cache **until TTL expires** (300 seconds) or it is evicted/busted.
- Every subsequent request to `/api/user` (or any variant collapsed to the same key) returns:
  - Admin data that **should have been restricted** to privileged contexts.
- No cookies or auth headers are considered for the cache key, so:
  - Anonymous users, different sessions, etc. all share the same poisoned cache entry.

---

### Prevention

| Mitigation                              | Where to Apply        | What It Prevents                                           |
|----------------------------------------|------------------------|------------------------------------------------------------|
| Reject CL+TE combination               | Edge / App server     | Eliminates CL.TE desync by enforcing unambiguous framing   |
| Disable backend connection reuse       | Front-end proxy       | Stops smuggled bytes from affecting subsequent requests    |
| Normalize / strip conflicting headers  | Front-end proxy       | Ensures only one framing mechanism is used end-to-end      |
| Include Cookie & Authorization in hash | Cache layer (Varnish) | Prevents cache key confusion across user/auth contexts     |
| Don’t cache POST or Set-Cookie         | Cache layer           | Avoids caching sensitive or stateful responses             |
| Use strong validation in app           | Application layer     | Rejects malformed / suspicious requests early              |
| Add security headers                   | Application layer     | Mitigates some browser-based exploitation vectors          |
| Regularly review proxy/cache configs   | Operations            | Catches unsafe defaults and regressions over time          |

Use the **vulnerable** configuration for teaching and demos, then switch to the **secure** configuration to show how each mitigation breaks the attack chain.

---

### Known Timing Sensitivities and Tips

- The attacker scripts intentionally sleep for **0.1–0.5 seconds** between smuggling and trigger requests:
  - This helps ensure the smuggled bytes are fully processed and the backend connection is re-used.
- If you do not see the expected behavior:
  - Increase sleep to 1–2 seconds.
  - Confirm all containers are healthy (`docker ps` and logs).
  - Inspect backend logs to verify hidden `/admin` and `/api/user` requests appear as expected.

