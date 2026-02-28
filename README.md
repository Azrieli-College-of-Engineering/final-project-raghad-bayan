# HTTP Request Smuggling + Cache Poisoning Lab

[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/Nt4zUlkt)

This repository is a **web security final project** that addresses **HTTP request smuggling** (CL.TE desynchronization) and **web cache poisoning** as real-world web security vulnerabilities. It provides an intentionally vulnerable three-tier stack (HAProxy → Varnish → Flask), raw-socket Python attack scripts that exploit parsing differences between front-end and back-end, and hardened configurations that block smuggling and allow cache purge. The project demonstrates how systems that place a reverse proxy and cache in front of an application can expose critical endpoints and serve poisoned responses to all users—and how to detect, mitigate, and recover with application-level validation, strict cache keys, and operational purge.

---

## About This Project

This is a cybersecurity / web security project focused on **CL.TE request smuggling** and **cache poisoning**. In typical deployments, a front-end proxy (e.g. HAProxy) and a cache (e.g. Varnish) sit in front of the back-end. When a request contains both `Content-Length` and `Transfer-Encoding: chunked`, the front-end may use one header to frame the request while the back-end uses the other; the leftover bytes in the TCP stream are then interpreted as the *next* request. Attackers can smuggle a hidden request (e.g. to `/admin` or a privileged `/api/user`), and if that response is cached under a key shared with normal users, every subsequent client receives the poisoned content until the cache entry expires or is purged. This lab implements a vulnerable stack, attack scripts for request smuggling and cache poisoning, hardened proxy/cache/app configs, and a cache-purge mechanism so that the vulnerability, exploitation, and remediation can be understood and reproduced.

**Attached documentation:** An academic final project report (Word/PDF) was prepared for submission. If it is not visible in this repository, it was submitted separately (e.g., via the course submission system). The report describes the vulnerability, theoretical background, the lab environment, proof-of-concept attack scenarios, defense mechanisms (with references to the codebase), and sources.

---

## Lab Overview

The main deliverable lives in the **`smuggling-lab/`** directory. The stack is:

```
[Attacker]  →  [HAProxy :80]  →  [Varnish :6081]  →  [Flask :5000]
```

- **HAProxy** — front-end reverse proxy; forwards requests with both CL and TE; keep-alive to back-end.
- **Varnish** — HTTP cache for `/api/*`; vulnerable config uses a path-only cache key for `/api/user`.
- **Flask** — back-end API; honors `Transfer-Encoding: chunked` and stops at the chunk terminator, leaving smuggled bytes in the connection buffer.

Full documentation (architecture, attack scenarios, defenses, installation, and key findings) is in **[smuggling-lab/README.md](smuggling-lab/README.md)**.

---

## Quick Start

```bash
git clone https://github.com/Azrieli-College-of-Engineering/final-project-raghad-bayan
cd final-project-raghad-bayan/smuggling-lab
docker compose up --build
```

In a second terminal:

```bash
cd final-project-raghad-bayan/smuggling-lab/attacker
python smuggle_clte.py
python cache_poison.py
```

See [smuggling-lab/README.md](smuggling-lab/README.md) for applying defenses, running the cache purge tool, and verifying that attacks are blocked.
