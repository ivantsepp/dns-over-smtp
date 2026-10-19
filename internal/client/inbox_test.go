package client

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"dns-over-smtp/internal/protocol"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/miekg/dns"
)

type relaySession struct {
	acceptingSession
	deliver func([]byte)
}

func (r relaySession) Data(reader io.Reader) error {
	b, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	r.deliver(b)
	return nil
}

func testTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestRelayBounceThroughTLSIMAP(t *testing.T) {
	for _, scenario := range []struct{ deliver, trusted bool }{{true, true}, {false, true}, {true, false}} {
		deliver, trusted := scenario.deliver, scenario.trusted
		t.Run(fmt.Sprintf("deliver=%v/trusted=%v", deliver, trusted), func(t *testing.T) {
			var mu sync.Mutex
			var bounce []byte
			relay := gosmtp.NewServer(gosmtp.BackendFunc(func(*gosmtp.Conn) (gosmtp.Session, error) {
				return relaySession{deliver: func(raw []byte) {
					q, id, err := protocol.ParseQuery(raw)
					if err != nil {
						t.Error(err)
						return
					}
					m := new(dns.Msg)
					m.SetReply(q)
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.99")}}
					payload, err := protocol.EncodeResponse(m, id)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					defer mu.Unlock()
					bounce = []byte("Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nDelivery failed\r\n--b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: rfc822; dns@localhost\r\nAction: failed\r\nStatus: 5.0.0\r\nDiagnostic-Code: smtp; 550 5.0.0 " + payload + "\r\n--b--\r\n")
				}}, nil
			}))
			relay.Domain = "localhost"
			config := directConfig(t, serveSMTP(t, relay))
			cert, roots := testTLS(t)
			plain, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := tls.NewListener(plain, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			defer listener.Close()
			var commands []string
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1] fixture ready\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						done <- nil
						return
					}
					fields := strings.Fields(line)
					if len(fields) < 2 {
						done <- fmt.Errorf("invalid IMAP command")
						return
					}
					mu.Lock()
					commands = append(commands, line)
					raw := append([]byte(nil), bounce...)
					mu.Unlock()
					tag := fields[0]
					switch strings.ToUpper(fields[1]) {
					case "CAPABILITY":
						fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1\r\n%s OK capability\r\n", tag)
					case "LOGIN":
						fmt.Fprintf(conn, "%s OK login\r\n", tag)
					case "EXAMINE":
						fmt.Fprintf(conn, "* 1 EXISTS\r\n* OK [UIDVALIDITY 1] valid\r\n* OK [UIDNEXT 7] next\r\n%s OK [READ-ONLY] examined\r\n", tag)
					case "UID":
						if strings.EqualFold(fields[2], "SEARCH") {
							if deliver {
								fmt.Fprintf(conn, "* SEARCH 6 7\r\n%s OK search\r\n", tag)
							} else {
								fmt.Fprintf(conn, "* SEARCH 6\r\n%s OK search\r\n", tag)
							}
						} else if strings.EqualFold(fields[2], "FETCH") && fields[3] == "7" {
							fmt.Fprintf(conn, "* 1 FETCH (UID 7 BODY[]<0> {%d}\r\n%s)\r\n%s OK fetched\r\n", len(raw), raw, tag)
						} else {
							done <- fmt.Errorf("unexpected UID command %s", line)
							return
						}
					default:
						done <- fmt.Errorf("unexpected IMAP command %s", line)
						return
					}
				}
			}()
			config.IMAPHost, _, _ = net.SplitHostPort(listener.Addr().String())
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			config.IMAPPort, _ = net.LookupPort("tcp", port)
			config.IMAPUser = "fixture-user"
			config.IMAPPass = "fixture-password"
			config.IMAPMailbox = "INBOX"
			config.TLSRootCAs = roots
			if !trusted {
				config.TLSRootCAs = nil
			}
			if !deliver {
				config.Timeout = 150 * time.Millisecond
			}
			q := new(dns.Msg)
			q.SetQuestion("relay.test.", dns.TypeA)
			m, err := New(config).Exchange(q)
			if !trusted {
				if err == nil {
					t.Fatal("untrusted TLS certificate accepted")
				}
				mu.Lock()
				sent := len(bounce) > 0
				mu.Unlock()
				if sent {
					t.Fatal("submitted query before verifying inbox TLS")
				}
			} else if deliver {
				if err != nil {
					t.Fatal(err)
				}
				if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.0.2.99" {
					t.Fatal("wrong relayed answer")
				}
			} else if err == nil {
				t.Fatal("missing bounce succeeded")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			transcript := strings.Join(commands, "")
			mu.Unlock()
			if trusted && (!strings.Contains(transcript, "EXAMINE") || strings.Contains(transcript, "STORE")) {
				t.Fatal("mailbox was not read-only")
			}
			if trusted && deliver && !strings.Contains(transcript, "BODY.PEEK[]<0.65537>") {
				t.Fatalf("fetch was not bounded and peeked: %s", transcript)
			}
		})
	}
}
