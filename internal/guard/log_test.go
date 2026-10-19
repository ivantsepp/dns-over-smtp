package guard

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLibraryLogRedaction(t *testing.T) {
	var output bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(old)
	l := EventLogger{Event: "smtp_session_error"}
	l.Printf("auth failed for %s: %s", "private@example.test", "fixture-secret")
	l.Println("private@example.test", "fixture-secret")
	if !strings.Contains(output.String(), "smtp_session_error") || strings.Contains(output.String(), "private@example.test") || strings.Contains(output.String(), "fixture-secret") {
		t.Fatalf("unsafe logs: %s", output.String())
	}
}
