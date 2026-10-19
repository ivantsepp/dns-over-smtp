package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpDoesNotExposeEnvironmentPasswords(t *testing.T) {
	t.Setenv("DNS_SMTP_HELP_TEST", "1")
	t.Setenv("SMTP_PASS", "fixture-smtp-secret")
	t.Setenv("IMAP_PASS", "fixture-imap-secret")
	command := exec.Command(os.Args[0], "-test.run=TestPasswordHelpProcess")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if !strings.Contains(string(output), "-imap-host") || strings.Contains(string(output), "fixture-smtp-secret") || strings.Contains(string(output), "fixture-imap-secret") {
		t.Fatal("help exposed credentials or did not print usage")
	}
}

func TestDecodeCLI(t *testing.T) {
	const payload = "V7WBgAABAAIAAAAAB2V4YW1wbGUDY29tAAABAAHADAABAAEAAAEsAARoFBeawAwAAQABAAABLAAErEKT8w=="
	path := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		fail  bool
	}{
		{"stdin", nil, payload, false},
		{"file", []string{"-input", path}, "", false},
		{"legacy flag", []string{"-bounce-file", path}, "", false},
		{"invalid", nil, "invalid!", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-test.run=TestDecodeProcess", "--", "-mode=decode"}, tc.args...)
			command := exec.Command(os.Args[0], args...)
			command.Env = append(os.Environ(), "DNS_SMTP_DECODE_TEST=1")
			command.Stdin = strings.NewReader(tc.stdin)
			output, err := command.CombinedOutput()
			if tc.fail {
				if err == nil {
					t.Fatal("invalid input returned success")
				}
				return
			}
			if err != nil {
				t.Fatalf("decode failed: %v: %s", err, output)
			}
			for _, want := range []string{"DNS-RESPONSE", "example.com.", "104.20.23.154", "172.66.147.243"} {
				if !strings.Contains(string(output), want) {
					t.Fatalf("missing %q in %s", want, output)
				}
			}
		})
	}
}

func TestDecodeProcess(t *testing.T) {
	if os.Getenv("DNS_SMTP_DECODE_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"dns-over-smtp"}, os.Args[i+1:]...)
			flag.CommandLine = flag.NewFlagSet("dns-over-smtp", flag.ExitOnError)
			main()
			return
		}
	}
	t.Fatal("missing decoder arguments")
}

func TestPasswordHelpProcess(t *testing.T) {
	if os.Getenv("DNS_SMTP_HELP_TEST") != "1" {
		return
	}
	os.Args = []string{"dns-over-smtp", "-help"}
	flag.CommandLine = flag.NewFlagSet("dns-over-smtp", flag.ExitOnError)
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
