package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"dns-over-smtp/internal/client"
	"dns-over-smtp/internal/inspect"
	"dns-over-smtp/internal/server"
	"github.com/miekg/dns"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "client", "client (UDP DNS proxy), server, query, or decode")
	smtpHost := flag.String("smtp-host", "localhost", "SMTP host to connect to (client/query)")
	smtpPort := flag.Int("smtp-port", 2525, "SMTP port to connect to (client/query)")
	smtpUser := flag.String("smtp-user", "", "SMTP authentication username")
	smtpPass := flag.String("smtp-pass", "", "SMTP password (defaults to SMTP_PASS environment variable)")
	smtpTLS := flag.Bool("smtp-implicit-tls", false, "Use implicit SMTP TLS, e.g. port 465")
	emailFrom := flag.String("email-from", "", "Return address receiving the bounce (client/query)")
	emailTo := flag.String("email-to", "dns@localhost", "Demo recipient address (all SMTP modes)")
	listen := flag.String("listen", "127.0.0.1:5353", "Local UDP DNS listen address (client)")
	smtpListen := flag.String("smtp-listen", "127.0.0.1:2525", "Inbound SMTP listen address (server)")
	smtpDomain := flag.String("smtp-domain", "localhost", "SMTP server hostname (server)")
	dnsServer := flag.String("dns-server", "8.8.8.8:53", "Fixed upstream DNS resolver (server)")
	tlsCert := flag.String("tls-cert", "", "PEM certificate for inbound STARTTLS (server)")
	tlsKey := flag.String("tls-key", "", "PEM private key for inbound STARTTLS (server)")
	rate := flag.Int("queries-per-minute", 60, "Query limit per connecting MTA IP (server)")
	imapHost := flag.String("imap-host", "", "IMAP host for relay-generated bounces (optional)")
	imapPort := flag.Int("imap-port", 993, "IMAP TLS port")
	imapUser := flag.String("imap-user", "", "IMAP username")
	imapPass := flag.String("imap-pass", "", "IMAP password (defaults to IMAP_PASS environment variable)")
	imapMailbox := flag.String("imap-mailbox", "INBOX", "IMAP mailbox to read without changing messages")
	timeout := flag.Duration("timeout", 90*time.Second, "Total SMTP/IMAP round-trip timeout")
	poll := flag.Duration("poll-interval", 3*time.Second, "IMAP polling interval")
	queryName := flag.String("query", "", "Domain to resolve (query mode)")
	queryType := flag.String("type", "A", "DNS record type (query mode)")
	var inputFile string
	flag.StringVar(&inputFile, "input", "-", "Base64, SMTP transcript or bounce .eml file, or - for stdin (decode mode)")
	flag.StringVar(&inputFile, "bounce-file", "-", "Alias for -input (decode mode)")
	flag.Parse()
	// Resolve secrets after parsing so -help cannot print them as defaults.
	if *smtpPass == "" {
		*smtpPass = os.Getenv("SMTP_PASS")
	}
	if *imapPass == "" {
		*imapPass = os.Getenv("IMAP_PASS")
	}
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch *mode {
	case "server":
		return server.New(&server.Config{ListenAddr: *smtpListen, Domain: *smtpDomain, Recipient: *emailTo, DNSServer: *dnsServer, TLSCert: *tlsCert, TLSKey: *tlsKey, QueriesPerMinute: *rate}).Start()
	case "client", "query":
		c := client.New(&client.Config{SMTPHost: *smtpHost, SMTPPort: *smtpPort, SMTPUser: *smtpUser, SMTPPass: *smtpPass, SMTPImplicitTLS: *smtpTLS, EmailFrom: *emailFrom, EmailTo: *emailTo, ListenAddr: *listen, IMAPHost: *imapHost, IMAPPort: *imapPort, IMAPUser: *imapUser, IMAPPass: *imapPass, IMAPMailbox: *imapMailbox, Timeout: *timeout, PollInterval: *poll})
		if *mode == "client" {
			return c.Start()
		}
		qtype, ok := dns.StringToType[strings.ToUpper(*queryType)]
		if !ok || *queryName == "" {
			return errors.New("query mode requires -query and a valid -type")
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(*queryName), qtype)
		answer, err := c.Exchange(m)
		if err != nil {
			return err
		}
		fmt.Println(answer)
		return nil
	case "decode":
		var r io.Reader = os.Stdin
		if inputFile != "-" {
			f, err := os.Open(inputFile)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		b, err := io.ReadAll(io.LimitReader(r, inspect.MaxInputBytes+1))
		if err != nil {
			return err
		}
		messages, err := inspect.Decode(b)
		if err != nil {
			return err
		}
		for _, message := range messages {
			fmt.Print(";; ", message.Kind)
			if message.RequestID != "" {
				fmt.Print(" request-id=", message.RequestID)
			}
			fmt.Println()
			fmt.Println(message.DNS)
		}
		return nil
	default:
		return errors.New("mode must be client, server, query or decode")
	}
}
