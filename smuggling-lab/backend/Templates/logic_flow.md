# Logical Flow — HTTP Request Smuggling + Cache Poisoning Lab

## System Architecture

```
[Attacker / Browser]
        │
        │  HTTP :80
        ▼
┌───────────────────┐
│   HAProxy 2.4     │  Reverse Proxy — forwards requests to Varnish
│   (frontend)      │  Vulnerable: passes both CL and TE headers
└────────┬──────────┘
         │  internal :6081
         ▼
┌───────────────────┐
│   Varnish 7       │  HTTP Cache — caches /api/* responses
│   (cache)         │  Vulnerable: path-only cache key (ignores auth)
└────────┬──────────┘
         │  internal :5000
         ▼
┌───────────────────┐
│   Flask / Python  │  Backend API — /api/user, /admin, /api/reset
│   (backend)       │  Vulnerable: honors Transfer-Encoding: chunked
└───────────────────┘
```

---

## Normal Request Flow (No Attack)

```
Client                  HAProxy             Varnish              Flask
  │                        │                   │                    │
  │── GET /api/user ──────►│                   │                    │
  │                        │── forward ───────►│                    │
  │                        │              [cache lookup]            │
  │                        │              HIT? ──────────────────►  │
  │                        │              MISS ────────────────────►│
  │                        │                   │◄── JSON response ──│
  │                        │                   │  [store in cache]  │
  │◄── JSON response ──────│◄── response ──────│                    │
```

---

## Attack Flow 1 — CL.TE Request Smuggling

**Root cause:** HAProxy uses `Content-Length`, Flask uses `Transfer-Encoding: chunked`.

```
Attacker                HAProxy              Flask (backend)
   │                       │                      │
   │  POST /               │                      │
   │  Content-Length: 44   │                      │
   │  Transfer-Encoding:   │                      │
   │    chunked            │                      │
   │  Body:                │                      │
   │   1\r\nX\r\n          │                      │
   │   0\r\n\r\n           │                      │
   │   GET /admin...  ─────►                      │
   │                       │── one request ──────►│
   │                       │  (CL covers all)     │
   │                       │               Flask reads chunked:
   │                       │               stops at 0\r\n\r\n
   │                       │               "GET /admin..." stays
   │                       │               in TCP buffer !!!
   │                       │                      │
   Victim ── GET /api/user ►│                      │
   │                       │── forward ──────────►│
   │                       │               Flask sees buffer first:
   │                       │               processes GET /admin
   │◄── admin response ────│◄─────────────────────│
```

---

## Attack Flow 2 — TE.CL Request Smuggling

**Root cause:** HAProxy uses `Transfer-Encoding: chunked`, Flask uses `Content-Length`.

```
Attacker                HAProxy              Flask (backend)
   │                       │                      │
   │  POST /               │                      │
   │  Transfer-Encoding:   │                      │
   │    chunked            │                      │
   │  Content-Length: 4    │                      │
   │  Body:                │                      │
   │   <hex>\r\n           │                      │
   │   GET /admin...       │                      │
   │   \r\n0\r\n\r\n  ─────►                      │
   │                       │  HAProxy reads full  │
   │                       │  chunked body ──────►│
   │                       │               Flask reads CL=4 bytes
   │                       │               only 4 bytes consumed
   │                       │               "GET /admin..." stays
   │                       │               in TCP buffer !!!
   │                       │                      │
   Victim ── GET /api/user ►│                      │
   │                       │── forward ──────────►│
   │                       │               Flask sees buffer first:
   │                       │               processes GET /admin
   │◄── admin response ────│◄─────────────────────│
```

---

## Attack Flow 3 — Cache Poisoning (via CL.TE)

```
Attacker              HAProxy         Varnish            Flask
   │                     │               │                  │
   │  [STEP 1]           │               │                  │
   │  GET /api/user ────►│──────────────►│                  │
   │                     │          CACHE MISS              │
   │                     │               │─────────────────►│
   │◄── role:standard ───│◄──────────────│◄── response ─────│
   │    X-Cache: MISS    │          [cached]                │
   │                     │               │                  │
   │  [STEP 2]           │               │                  │
   │  CL.TE smuggle ────►│──────────────►│─────────────────►│
   │  (embedded          │               │          Flask queues:
   │   GET /api/user     │               │          GET /api/user
   │   X-Admin-Auth)     │               │          + X-Admin-Auth
   │                     │               │                  │
   │  [STEP 3]           │               │                  │
   │  GET /api/user ────►│──────────────►│─────────────────►│
   │                     │               │          Flask processes
   │                     │               │          queued admin req
   │                     │               │◄── role:admin ───│
   │                     │          [CACHED! key=/api/user] │
   │◄── role:admin ──────│◄──────────────│                  │
   │                     │               │                  │
   │  [STEP 4]           │               │                  │
   User1 GET /api/user ─►│──────────────►│                  │
   │◄── role:admin ──────│◄── CACHE HIT ─│                  │
   User2 GET /api/user ─►│──────────────►│                  │
   │◄── role:admin ──────│◄── CACHE HIT ─│                  │
```

---

## Attack Flow 4 — Host Header Injection

```
Attacker                      HAProxy              Flask
   │                             │                    │
   │  POST /api/reset            │                    │
   │  X-Forwarded-Host:          │                    │
   │    evil.attacker.com   ─────►───────────────────►│
   │                             │             Flask builds reset link:
   │                             │             http://evil.attacker.com
   │                             │               /reset?token=SECRET
   │◄── reset_link: ─────────────│◄───────────────────│
   │    http://evil.attacker.com │                    │
   │    /reset?token=SECRET      │                    │
   │                             │                    │
   Victim receives email with link pointing to evil.attacker.com
   Victim clicks → token sent to attacker → account takeover
```

---

## Attack Flow 5 — Cache Deception

```
Attacker              Victim           Varnish            Flask
   │                    │                 │                  │
   │ [Send victim       │                 │                  │
   │  phishing link]    │                 │                  │
   │ ──────────────────►│                 │                  │
   │                    │                 │                  │
   │              GET /api/user/style.css │                  │
   │                    │────────────────►│                  │
   │                    │           CACHE MISS               │
   │                    │                 │─────────────────►│
   │                    │                 │  Flask ignores   │
   │                    │                 │  .css suffix →   │
   │                    │                 │  returns private │
   │                    │                 │◄── user data ────│
   │                    │           [CACHED as static asset] │
   │                    │◄── private data─│                  │
   │                    │                 │                  │
   │ GET /api/user/style.css (no cookie)  │                  │
   │────────────────────────────────────►│                  │
   │◄── victim's private data ───────────│                  │
   │    X-Cache: HIT                     │                  │
```

---

## Defense Summary

| Attack | Root Cause | Defense |
|--------|-----------|---------|
| CL.TE Smuggling | HAProxy passes both CL+TE headers | `haproxy_secure.cfg`: deny if CL+TE; `app_secure.py`: block TE:chunked |
| TE.CL Smuggling | Flask trusts CL over TE | `haproxy_tecl_secure.cfg`: strip TE header + deny; `http-server-close` |
| Cache Poisoning | Varnish cache key ignores auth | `varnish_secure.vcl`: include Cookie+Auth in hash; pass if Set-Cookie |
| Host Header Injection | Flask trusts X-Forwarded-Host | Validate Host against allowlist; never build URLs from request headers |
| Cache Deception | Varnish caches by extension | Never cache responses with Set-Cookie; add `Vary: Cookie` |