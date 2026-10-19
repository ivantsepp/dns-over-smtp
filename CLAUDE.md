# DNS over SMTP project guidance

This Go proof of concept returns DNS answers in **intentional final-DATA SMTP rejections**. The receiver does not send email. A submitting mail provider generates the bounce; a direct client receives the same diagnostic immediately.

## Commands

```sh
make build
make test
go vet ./...
gofmt -s -w main.go internal/
```

CI uses Go 1.27.2 from `go.mod`, runs tests/build/vet, and checks formatting. Keep tests offline: in-process loopback SMTP/DNS/TLS-IMAP fixtures are available in the client tests. Never send real provider emails during tests.

## Architecture

- `main.go`: client/server/query/decode CLI modes.
- `internal/server`: receive-only `go-smtp` listener, exact configured recipient, final DATA `550 5.0.0`, fixed upstream DNS resolution; no outbound mail path.
- `internal/client`: UDP DNS proxy and one-shot exchange; parse direct SMTP rejection or retrieve provider-generated DSNs through read-only TLS IMAP. No mock responses.
- `internal/protocol`: MIME/DSN parsing, bounded base64 DNS packets, random request correlation, DNS question validation, and <=512-byte SMTP reply formatting.
- `internal/guard`: dependency circuit breaker and library log adapters that discard sensitive fields.

Machine query bodies have `DNS-QUERY: <32-hex-id>` on the first line and base64 wire data in 64-character lines. Accept both legacy single-line and whitespace-wrapped payloads within one plain-text MIME part. `protocol.DecodePayload` checks strict base64, all declared DNS section counts and the consumed wire offset before treating a prefix as complete; `dns.Msg.Unpack` alone also accepts header-only and trailing-byte cases. Never join different MIME parts or fall back to HTML. Manual queries use `A example.com` or just `example.com` (defaults to A) on the first nonblank body line; later signature lines are ignored. Bare queries require one nonempty plain-text part, and domain-only shorthand requires a dotted ASCII name. Record types are case-insensitive and the subject is unrestricted. Keep `DNS-QUERY: A example.com` compatible. Reply diagnostic: `DNS-RESPONSE: <same-id> <base64-wire-answer>`, optionally followed by a small readable summary; DSN folding inside its base64 is supported.

The DNS answer cap is 300 bytes after compression. Remove whole record sets and set TC if it does not fit. The library's `Msg.Truncate` enforces a 512-byte minimum, so it cannot implement this cap. There is no protocol for retrieving an oversized answer afterward.

## Conventions

Use `miekg/dns` for DNS serialization. Match both correlation ID and DNS transaction/question fields before serving a response. On local proxy failures, return SERVFAIL rather than dropping the query. Reject empty, multiple, transfer/ANY/meta/reserved questions and unexpected additional records. Reject specific forbidden query types; CAA, URI and other ordinary high-numbered types must remain valid. A valid bare first-line query takes precedence over later `DNS-QUERY:` markers in the same body. Preserve legacy tagged queries and duplicate-marker checks when parsing tagged input.

Bound all network operations, messages, MIME depth, rate maps and concurrency. SMTP authentication requires verified TLS; IMAP is always verified TLS and uses EXAMINE/BODY.PEEK. Never delete inbox messages or mark them seen. Ignore attached original messages when extracting a DSN answer. Keep structured logs free of credentials, email addresses and query names. Public defaults remain loopback; exposure requires explicit flags.

Keep README/config examples aligned with real flags. Provider DSN preservation is unverified until a live interoperability test is explicitly authorized and completed.
