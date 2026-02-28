vcl 4.0;

backend default {
    .host = "backend";
    .port = "5000";
}

sub vcl_recv {
    if (req.method == "PURGE") {
        if (req.http.X-Purge-Key == "internal-purge-secret") {
            return(purge);
        }
        return(synth(403, "Forbidden"));
    }
    if (req.method != "GET" && req.method != "HEAD") {
        return(pass);
    }
    if (req.http.Authorization || req.http.Cookie) {
        return(pass);
    }
    return(hash);
}

sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.Host);
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
    } else {
        set resp.http.X-Cache = "MISS";
    }
}
