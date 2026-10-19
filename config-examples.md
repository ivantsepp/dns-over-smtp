# Configuration examples

## Server: receive queries, return answers in SMTP rejections

```sh
./dns-over-smtp -mode=server \
  -smtp-listen=127.0.0.1:2525 \
  -smtp-domain=localhost \
  -email-to=dns@localhost \
  -dns-server=8.8.8.8:53 \
  -queries-per-minute=60
```

Server mode does not use `-smtp-host`, `-smtp-user`, `-smtp-pass`, or `-email-from`. For a public MX receiver, configure port 25, a real SMTP hostname/recipient, and optional `-tls-cert`/`-tls-key` files. See [hosting instructions](README.md#host-a-public-demo).

## Direct query

```sh
./dns-over-smtp -mode=query \
  -smtp-host=localhost -smtp-port=2525 \
  -email-from=you@local.test -email-to=dns@localhost \
  -query=example.com -type=AAAA -timeout=10s
```

## Query through an email provider

Set the password environment variables `SMTP_PASS` and `IMAP_PASS` securely first. The `.example` values below are placeholders for the actual endpoints and addresses supported by your provider.

```sh
./dns-over-smtp -mode=query \
  -smtp-host=smtp.provider.example -smtp-port=587 \
  -smtp-user=you@provider.example \
  -email-from=you@provider.example -email-to=dns@demo.example \
  -imap-host=imap.provider.example -imap-port=993 \
  -imap-user=you@provider.example -imap-mailbox=INBOX \
  -query=example.com -type=A -timeout=90s -poll-interval=3s
```

For SMTP port 465, add `-smtp-implicit-tls`. IMAP always uses TLS. Set a different `-imap-mailbox` if your provider files bounces elsewhere. Password flags remain available, but environment variables avoid putting passwords in process arguments or shell history. No OAuth2 authentication is implemented.

## UDP DNS proxy

Use the same transport options as query mode, with `-mode=client -listen=127.0.0.1:5353`. Omit `-query` and `-type`.

```sh
dig @127.0.0.1 -p 5353 +time=90 +tries=1 example.com A
```

Large responses are truncated; this single-line bounce protocol does not recover larger answers through a TCP retry.

## Decode a capture or saved delivery failure

```sh
./dns-over-smtp -mode=decode -input=smtp-conversation.txt
pbpaste | ./dns-over-smtp -mode=decode
./dns-over-smtp -mode=decode -input=bounce.eml
```

For captures, paste bare base64, a `DNS-QUERY:`/`DNS-RESPONSE:` line, or the complete SMTP conversation. The command displays all captured queries and responses. No DNS requests are sent. For saved mail, use the complete original `.eml`, including MIME headers and the machine-readable delivery-status part. `-bounce-file` is an alias for `-input`; stdin is the default.

## Environment variables actually supported

| Variable | Meaning |
|---|---|
| `SMTP_PASS` | Default value for `-smtp-pass` |
| `IMAP_PASS` | Default value for `-imap-pass` |

Other settings use explicit CLI flags. `-help` lists all options.
