package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
)

func TestWriterAppendAndNil(t *testing.T) {
	dir := t.TempDir()
	w, err := audit.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := w.Write(context.Background(), audit.Event{
		InsertID: "1", PrincipalID: "p", Operation: "op", StatusCode: 200,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(context.Background(), audit.Event{InsertID: "2", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Write(ctx, audit.Event{InsertID: "3"}); err == nil {
		t.Fatal("expected canceled")
	}

	var nilW *audit.Writer
	if err := nilW.Write(context.Background(), audit.Event{}); err != nil {
		t.Fatal(err)
	}
	if err := nilW.Close(); err != nil {
		t.Fatal(err)
	}
}
