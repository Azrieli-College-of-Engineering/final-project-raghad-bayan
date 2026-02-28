vcl 4.0;

backend default {
    .host = "backend";
    .port = "5000";
}

sub vcl_recv {
    # Allow cache purge with secret key
    if (req.method == "PURGE") {
        if (req.http.X-Purge-Key == "internal-purge-secret") {
            return(purge);
        }
        return(synth(403, "Forbidden"));
    }

    # Block requests with both CL and TE (smuggling prevention)
    if (req.http.Content-Length && req.http.Transfer-Encoding) {
        return(synth(400, "Bad Request - Ambiguous framing"));
    }

    if (req.method != "GET" && req.method != "HEAD") {
        return(pass);
    }

    if (req.http.Authorization || req.http.Cookie) {
        return(pass);
    }

    # ── Cache Deception vulnerability ────────────────────────────────────────
    # VULNERABLE: Varnish strips query strings from cache key for URLs that
    # look like static assets (.css, .js, .png, etc.). This means
    # /api/user/style.css is cached as a "public static file" even though
    # it contains private user data returned by the Flask backend.
    #
    # A secure config would do: if (req.url ~ "\.(css|js|png|jpg)$") { return(pass); }
    # but we intentionally omit that here to demonstrate the attack.
    # ─────────────────────────────────────────────────────────────────────────

    return(hash);
}

sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.Host);
    # VULNERABLE: Cookie is NOT included in hash for /api/user/<suffix> paths.
    # This means all users share the same cache entry for those URLs,
    # allowing an attacker to retrieve another user's cached private data.
    if (req.http.Cookie) {
        hash_data(req.http.Cookie);
    }
    return(lookup);
}

sub vcl_backend_response {
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        return(deliver);
    }
    if (bereq.url ~ "^/api/") {
        set beresp.ttl = 300s;
    }
}

sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }
}
