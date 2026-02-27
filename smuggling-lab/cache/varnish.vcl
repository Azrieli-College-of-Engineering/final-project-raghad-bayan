vcl 4.1;

backend default {
    .host = "smuggling-backend";
    .port = "5000";
}

sub vcl_recv {
    if (req.method == "PRI") {
        return (synth(405));
    }

    # Do not cache POST
    if (req.method == "POST") {
        return (pass);
    }

    # Intentionally insecure: ignore Cookie and Authorization for cache key
    unset req.http.Cookie;
    unset req.http.Authorization;

    # Let everything through as HTTP/1.1 keep-alive
}

sub vcl_backend_response {
    # Cache GET /api/* for 300s if backend allows it
    if (bereq.method == "GET" && bereq.url ~ "^/api/") {
        if (beresp.ttl <= 0s) {
            set beresp.ttl = 300s;
        }
    }

    # Never cache POST responses (defense-in-depth, though we already pass POSTs)
    if (bereq.method == "POST") {
        set beresp.ttl = 0s;
        return (pass);
    }
}

sub vcl_hash {
    # Base hash on host and URL path
    hash_data(req.http.host);

    if (req.url ~ "^/api/user") {
        # Intentionally collapse query parameters:
        # all /api/user?* share a single cache key
        hash_data("/api/user");
    } else {
        hash_data(req.url);
    }

    # Intentionally DO NOT include Cookie or Authorization
}

