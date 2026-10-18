### Structure

```json
{
  "type": "trojan",
  "tag": "trojan-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "tls": {},
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "http/1.1": {
      "server": "127.0.0.1",
      "server_port": 8081
    }
  },
  "multiplex": {},
  "transport": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

Required unless `http_auth` is configured.

Trojan users.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### fallback

!!! failure ""

    There is no evidence that GFW detects and blocks Trojan servers based on HTTP responses, and opening the standard http/s port on the server is a much bigger signature.

Fallback server configuration. Disabled if `fallback` and `fallback_for_alpn` are empty.

#### fallback_for_alpn

Fallback server configuration for specified ALPN.

If not empty, TLS fallback requests with ALPN not in this table will be rejected.

#### multiplex

See [Multiplex](/configuration/shared/multiplex#inbound) for details.

#### transport

V2Ray Transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).

#### http_auth (Advoo extension)

Optional external authentication, mutually exclusive with static `users`:

```json
{
  "http_auth": {
    "url": "http://dotai-backend.prod.api.dotai.internal/dotai/internal/proxy/token/query",
    "service_token": "<injected internal service credential>",
    "timeout": "3s"
  }
}
```

The callback receives the Trojan SHA-224 digest, not the plaintext password. The HTTP adapter posts `{"digest":"<56 lowercase hex>"}` with `X-Gateway-Service-Token`. It accepts only HTTP 200 and `{"code":0,"result":{"valid":true,"email":"user@example.com"}}`.

The returned email becomes the routing user and appears with source IP and destination in TCP/UDP connection logs. Credentials are never logged. Responses are not cached; errors, malformed responses, redirects and timeouts deny authentication without falling back to static credentials. Default timeout is 3 seconds, maximum 30 seconds. Use the test Java hostname for test credentials; production requires the Java endpoint and schema to be deployed first. Existing established connections are not terminated when a token is replaced or expires.
