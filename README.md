# DNS over SMTP

A deliberately impractical DNS transport: ask a DNS question by email and get the answer inside a delivery-failure notification.

The demo server **never sends email**. It reads an incoming SMTP message, resolves the question through a fixed DNS upstream, and rejects the message at the end of DATA with `550 5.0.0`. The rejection contains the DNS answer. When you use a normal mail provider, that provider generates the bounce back to your mailbox. Your demo server has no outbound mail queue or sending IP reputation to maintain.

## Build

Use the Go version required by [go.mod](go.mod) or newer:

```sh
go mod download
make build
go test ./...
```

`make build` and `make build-all` disable cgo. Linux binaries are statically linked, so they do not require the build machine's glibc version. CI uses the same `make build-all` recipe and checks that the Linux artifact is statically linked before uploading it.

To use a CI build, open a successful run under GitHub **Actions**, download and extract the **binaries** artifact, then copy `dns-over-smtp-linux-amd64` to an `x86_64` Linux VM. Run `chmod +x dns-over-smtp-linux-amd64` before starting it. If an older artifact reports a missing `GLIBC_...` version, replace it with a build from the updated workflow.

## Try it locally

Start the receive-only server:

```sh
./dns-over-smtp -mode=server \
  -smtp-listen=127.0.0.1:2525 \
  -email-to=dns@localhost \
  -dns-server=8.8.8.8:53
```

In another terminal, make a real query over a direct SMTP connection:

```sh
./dns-over-smtp -mode=query \
  -smtp-host=localhost -smtp-port=2525 \
  -email-from=you@local.test -email-to=dns@localhost \
  -query=example.com -type=A
```

The client recognizes the intentional SMTP rejection and prints the decoded DNS response. There are no mock answers or artificial sleeps.

You can also run a local UDP DNS proxy:

```sh
./dns-over-smtp -mode=client \
  -smtp-host=localhost -smtp-port=2525 \
  -email-from=you@local.test -email-to=dns@localhost

dig @127.0.0.1 -p 5353 example.com A
```

## Try it from an ordinary email account

Once the server is reachable through your demo domain's MX record, send a plain-text email to its configured recipient. The subject is unrestricted. Put the query on the first nonblank line of the body:

```text
A example.com
```

Or send just a dotted domain name to look up its A records:

```text
example.com
```

Record types are case-insensitive; AAAA, MX, TXT, CAA and URI work too. ANY and zone transfers are rejected. Send one query per message. Later body lines are ignored for these bare queries, including any `DNS-QUERY:` markers in a signature or copied text. The query must fit on one line in one nonempty plain-text MIME part. The `DNS-QUERY: A example.com` form is still accepted for compatibility; no prefix is required for manual queries.

For manual Gmail tests, the short form above avoids copying a binary packet. Machine queries also accept line breaks between the request ID and payload, and spaces, tabs or line breaks inside the base64. The receiver reads the decoded plain-text MIME part; a duplicate HTML representation is ignored. A payload is never assembled from different MIME parts.

The expected result is a **failed-delivery notification**. For a human-readable query, its remote-server diagnostic contains readable DNS records, for example:

```text
550 5.0.0 DNS answer: example.com. A; status=NOERROR; example.com. 60 IN A 192.0.2.42
```

The address above is illustrative. Each record shows its name, TTL, class, type, and value. MX, TXT, CAA and other record types are readable too. Empty answers say `no answers` and include the DNS status, such as `NOERROR`, `NXDOMAIN` or `SERVFAIL`. Answers may also include labeled authority and additional records. If the text cannot fit in the SMTP reply, only complete records that fit are shown, followed by `[truncated]`. The SMTP rejection is intentional for successful and unsuccessful DNS lookups alike. Restart or redeploy the server after updating it to use this response format.

Machine queries using `DNS-QUERY: <request-id> <base64>` still receive `DNS-RESPONSE: <request-id> <base64>` and an optional short summary. Save their complete bounce as an `.eml` file to inspect all returned records:

```sh
./dns-over-smtp -mode=decode -bounce-file=bounce.eml
```

For saved machine-query bounce mail, the decoder reads SMTP `Diagnostic-Code` fields inside a `message/delivery-status` MIME part, including folded base64. Use the complete `.eml`; attached original messages are never treated as answers. Saved outgoing query `.eml` files can also be decoded through their plain-text MIME part. Human-readable answers can be read directly and do not need the base64 decoder.

## Decode a Wireshark capture or base64 payload

The base64 token contains a binary DNS packet, not text. Decode mode displays its header, flags, question, and all answer/authority/additional records without contacting a server. It accepts a bare token, complete `DNS-QUERY:` / `DNS-RESPONSE:` lines, or an entire copied SMTP conversation. Every marked packet is displayed in capture order with its request ID.

Rebuild after updating the source (`make build`). On macOS, copy the payload, lines, or conversation from Wireshark and run:

```sh
pbpaste | ./dns-over-smtp -mode=decode
```

Or save the conversation to a text file:

```sh
./dns-over-smtp -mode=decode -input=smtp-conversation.txt
```

To paste directly into a terminal, run `./dns-over-smtp -mode=decode`, paste the text, and press Ctrl-D on a fresh line. Base64 may contain whitespace or line breaks, including inside marked query/response payloads. Saved query and bounce `.eml` inputs are supported too; `-bounce-file` remains an alias for `-input`. Both default to stdin (`-`). Input is limited to 1 MiB and 128 captured packets; malformed input returns a nonzero exit status. The automated client still requires a matching request ID, DNS question and valid delivery-status diagnostic.

## Automated client through a mail provider

The client can submit a query through your SMTP provider and retrieve the resulting bounce over TLS IMAP. IMAP is connected before submission so an immediately arriving bounce is not missed. Messages remain unread and are never deleted.

Set `SMTP_PASS` and `IMAP_PASS` securely in your environment using the credentials supported by your provider. Then configure its actual submission and IMAP endpoints:

```sh
./dns-over-smtp -mode=query \
  -smtp-host=smtp.provider.example -smtp-port=587 \
  -smtp-user=you@provider.example \
  -email-from=you@provider.example -email-to=dns@demo.example \
  -imap-host=imap.provider.example -imap-port=993 \
  -imap-user=you@provider.example \
  -timeout=90s -poll-interval=3s \
  -query=example.com -type=A
```

Replace the `.example` endpoints and addresses. IMAP is always encrypted with certificate verification. SMTP uses STARTTLS when advertised and refuses authentication without encryption. For implicit SMTP TLS on port 465, add `-smtp-implicit-tls`. Username/password authentication is supported; OAuth2 is not implemented.

For DNS proxy mode, replace `-mode=query` with `-mode=client` and omit `-query`/`-type`. Email can exceed a normal DNS client's timeout, so for an experiment use `dig +time=90 +tries=1 ...`, or prefer one-shot query mode.

If a relay accepts the query and no IMAP host is configured, the client reports an error instead of returning a fake DNS answer.

## Host a public demo

You need a host that allows **inbound TCP port 25**, plus a domain whose MX record points at that host. The SMTP hostname needs a corresponding address record. Outbound access to the configured DNS resolver is also required. Ordinary mail providers deliver to port 25; a listener only on 2525 supports the direct demo.

```sh
./dns-over-smtp -mode=server \
  -smtp-listen=0.0.0.0:25 \
  -smtp-domain=smtp.demo.example \
  -email-to=dns@demo.example \
  -dns-server=8.8.8.8:53 \
  -tls-cert=/path/to/fullchain.pem \
  -tls-key=/path/to/privkey.pem
```

Supply a valid certificate/key pair for your hostname to advertise STARTTLS. Port 25 may require a service configured with permission to bind it. The server needs neither SMTP credentials nor an inbox. It accepts only the configured recipient, rejects ordinary mail, and never relays messages or generates its own bounces.

Defaults: loopback SMTP on 2525, loopback UDP DNS on 5353, 64 SMTP connections, 16 upstream lookups, 64 KiB messages, 20-second SMTP I/O timeouts, and 60 queries per minute per connecting MTA IP. Adjust the last limit with `-queries-per-minute`; users of the same provider may share an MTA IP. Five consecutive dependency failures pause further attempts for 30 seconds.

## Protocol and limits

Machine-generated query bodies contain:

```text
DNS-QUERY: <32-character-random-hex-id>
<base64-DNS-query split into lines of at most 64 characters>
```

The receiver also accepts the original single-line form. Whitespace inside the base64 is ignored within that MIME part. The client emits short lines because email software may rewrap body text; the email format recommends a maximum of 78 characters per line ([RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html#section-2.1.1)). Restart or redeploy an already-running SMTP receiver after rebuilding to pick up the new parser.

For machine queries, the final server response is a single SMTP reply line:

```text
550 5.0.0 DNS-RESPONSE: <same-id> <base64-DNS-response> [optional-readable-summary]
```

Text queries (`A example.com`, `example.com`, or the legacy `DNS-QUERY: A example.com`) receive the readable diagnostic shown above, without a base64 packet or request ID. Response format follows the query inside the decoded MIME body, regardless of the email's content-transfer encoding.

Both response formats keep the complete SMTP line within **512 bytes**. Machine DNS replies are compressed and capped at **300 wire bytes**; larger answers lose complete record sets and carry the DNS truncation flag. Human-readable replies instead fit complete textual records within the SMTP line budget and mark omitted records or upstream truncation with `[truncated]`. This prototype has no mechanism to recover a larger answer by retrying; the local DNS proxy currently supports UDP only. Upstream UDP truncation is retried over TCP before formatting the bounce. Resolver failures are returned as SERVFAIL in the request's response format.

The automated client correlates both the random request ID and DNS transaction/question fields. These checks prevent mixups, but do not authenticate answers cryptographically. Queries and replies are visible to mail infrastructure.

**Provider interoperability is not guaranteed.** A mail provider may omit, rewrite, or truncate the diagnostic, or deliver a bounce outside the client's timeout. Local tests cover the SMTP rejection and a simulated SMTP-relay/TLS-IMAP round trip; live Gmail/Outlook delivery has not been tested. This is a small-answer demo, not a production DNS service.

See [configuration examples](config-examples.md) for the CLI flags.
