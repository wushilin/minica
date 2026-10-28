# Running MiniCA behind an Nginx reverse proxy

MiniCA speaks plain HTTP. The usual deployment puts a reverse proxy in front
of it that terminates TLS, and keeps MiniCA itself on a network nothing else
can reach. This page shows that with Docker Compose and Nginx; Caddy, Traefik
or Apache work the same way.

## What MiniCA needs to know

| Setting | Why |
| --- | --- |
| `MINICA_PUBLIC_BASE_URL=https://ca.example.com/minica` | The address browsers and clients use. It goes into the CRL distribution URL of every issued certificate and into the public links on the CA pages, so it must be the proxy's URL, not the container's. |
| `MINICA_BASE_PATH=/minica` (default) | The path prefix MiniCA serves under. Keep it identical on both sides of the proxy (`location /minica/` → `proxy_pass .../minica/`), or set it to `/` and dedicate a hostname. |
| `MINICA_SECURE_COOKIES=true` | Marks the CSRF/flash cookies `Secure`. Enable when every browser reaches MiniCA over HTTPS. |

Basic auth needs nothing special: Nginx forwards the `Authorization` header as
is. Do **not** add `auth_basic` in Nginx on top of it, or users get two
prompts. If an authenticating proxy (Authelia, oauth2-proxy, ...) is to sign
users in instead, see [Header authentication](#header-authentication-sso)
below.

## Compose file with an isolated network

MiniCA does not need internet access. It is attached only to an `internal`
network; Nginx sits on that network and on the one that is exposed.

```yaml
networks:
  edge:
  no-internet:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.30.10.0/24

volumes:
  minica-data:

services:
  minica:
    image: wushilin/minica:<version>
    container_name: minica
    environment:
      MINICA_PUBLIC_BASE_URL: https://ca.example.com/minica
      MINICA_SECURE_COOKIES: "true"
      MINICA_ADMIN_PASSWORD: "$$2b$$12$$..."   # bcrypt hash; '$' doubled for compose
    volumes:
      - minica-data:/data
    security_opt:
      - no-new-privileges:true
    networks:
      - no-internet
    restart: unless-stopped

  nginx:
    image: nginx:1.27-alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/minica.conf:ro
      - ./tls:/etc/nginx/tls:ro       # fullchain.pem + privkey.pem for ca.example.com
    networks:
      - edge
      - no-internet
    depends_on:
      - minica
    restart: unless-stopped
```

`MINICA_ADMIN_PASSWORD` is best supplied from an `env_file` or a secret; the
`$$` doubling is only needed when the hash is written into the compose file
itself. Nginx reaches MiniCA as `http://minica:9988` through the internal
network; nothing publishes port 9988 on the host.

## nginx.conf

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name ca.example.com;

    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;

    # Backup restores upload the whole YAML backup; the default 1m is too small.
    client_max_body_size 64m;

    location = / {
        return 302 /minica/;
    }

    location /minica/ {
        proxy_pass http://minica:9988/minica/;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;      # key generation (RSA 8192) can take a while
    }
}
```

The TLS certificate for `ca.example.com` itself can of course be issued by a
MiniCA CA; see [Trusting a MiniCA certificate authority](trusting-the-ca.md)
for installing that CA on the clients.

Serving MiniCA at the root of a dedicated hostname instead: set
`MINICA_BASE_PATH=/` and `MINICA_PUBLIC_BASE_URL=https://ca.example.com`, and
use `location / { proxy_pass http://minica:9988/; ... }`.

## Header authentication (SSO)

If Nginx runs `auth_request` against Authelia, oauth2-proxy or similar, that
proxy can tell MiniCA who the user is through request headers instead of
Basic auth:

```yaml
    environment:
      MINICA_HEADER_AUTH_ENABLE: "true"
      MINICA_HEADER_USERNAME: Remote-User       # header with the user id
      MINICA_HEADER_GROUP: Remote-Groups        # header with the group list
      MINICA_HEADER_ADMIN_GROUP: minica-admins
      MINICA_HEADER_VIEWER_GROUP: minica-users
      MINICA_TRUSTED_REMOTE_1: 172.30.10.0/24   # the internal network above
```

Two things matter here:

- `MINICA_TRUSTED_REMOTE_1..10` must list the proxy. MiniCA checks the TCP
  peer of each connection against this list and only then believes the
  identity headers; with header auth enabled and no trusted remote, the
  server refuses to start. Container IPs change, so list the internal
  network's subnet rather than one address.
- In the `location /minica/` block, set the headers from the auth response
  (`proxy_set_header Remote-User $user; proxy_set_header Remote-Groups $groups;`
  after `auth_request_set`), and make sure a client cannot inject them: the
  `proxy_set_header` lines overwrite whatever the client sent.

Basic auth stays available for requests without identity headers (the Go CLI
uses it), unless `MINICA_BASIC_AUTH_ENABLE=false`.

## Notes

- The web pages load Bootstrap's stylesheet from `cdn.jsdelivr.net` in the
  **browser**. MiniCA itself never needs outbound access, but a browser on a
  network without internet gets an unstyled (still working) page.
- The public CA index (`/minica/`), the CA certificates
  (`/minica/<ca-id>/download`), the truststores and the CRLs
  (`/minica/crl/<ca-id>`) need no login by design, so clients can fetch the
  trust anchor and revocation list without credentials. Everything else
  requires a user.
