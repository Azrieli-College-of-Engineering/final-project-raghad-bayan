vcl 4.1;

backend default {
    .host = "smuggling-backend";
    .port = "5000";
}

sub vcl_recv {
    if (req.method == "PRI") {
        return (synth(405));
    }

    # Never cache POST
    if (req.method == "POST") {
        return (pass);
    }
}

sub vcl_backend_response {
    # Never cache responses that set cookies
    if (beresp.http.Set-Cookie) {
        set beresp.ttl = 0s;
        return (pass);
    }
}

sub vcl_hash {
    # Include host and full URL
    hash_data(req.http.host);
    hash_data(req.url);

    # Include Cookie and Authorization in cache key
    if (req.http.Cookie) {
        hash_data(req.http.Cookie);
    }
    if (req.http.Authorization) {
        hash_data(req.http.Authorization);
    }
}

sub vcl_deliver {
    # Make it explicit that cache varies by Cookie
    if (resp.http.Vary) {
        set resp.http.Vary = resp.http.Vary ", Cookie";
    } else {
        set resp.http.Vary = "Cookie";
    }
}

