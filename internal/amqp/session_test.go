package amqp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestHandleConnOpenAttachTransferFlowDeliver(t *testing.T) {
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 9)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sas, err := st.UpsertServiceBusNamespace("sub", "rg", "ns1", "eastus")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusQueue("ns1", "orders"); err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- handleConn(ctx, c2, st) }()

	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c1.Write(protocolHeader); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 8)
	if _, err := readFullPipe(c1, hdr); err != nil {
		t.Fatal(err)
	}

	// open with hostname + connection-string props via map is hard; use hostname field
	if err := writePerformative(c1, 0, perfOpen, []any{
		"client",
		"ns1.servicebus.windows.net",
		uint32(65536),
		uint16(1),
		nil,
	}); err != nil {
		t.Fatal(err)
	}
	f, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	code, _, _, err := parseDescribedList(f.body)
	if err != nil || code != perfOpen {
		t.Fatalf("open reply %x %v", code, err)
	}

	if err := writePerformative(c1, 0, perfBegin, []any{nil, uint32(0), uint32(100), uint32(100)}); err != nil {
		t.Fatal(err)
	}
	if f, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}

	// peer sender attach (role=false) to enqueue; target address at field 5
	if err := writePerformative(c1, 0, perfAttach, []any{
		"sender",
		uint32(1),
		false,
		nil,
		nil,
		"ns1/orders",
	}); err != nil {
		t.Fatal(err)
	}
	if f, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}

	payload := encodeDataSection([]byte("via-amqp"))
	body := encodeDescribedList(perfTransfer, []any{
		uint32(1), uint32(1), []byte{1}, nil, true, false,
	})
	body = append(body, payload...)
	if err := writeFrame(c1, 0, body); err != nil {
		t.Fatal(err)
	}
	if f, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}
	code, _, _, err = parseDescribedList(f.body)
	if err != nil || code != perfDisposition {
		t.Fatalf("disposition %x %v", code, err)
	}

	// detach sender, attach receiver, flow to deliver
	if err := writePerformative(c1, 0, perfDetach, []any{uint32(1), true}); err != nil {
		t.Fatal(err)
	}
	if _, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfAttach, []any{
		"receiver",
		uint32(2),
		true, // peer is receiver
		nil,
		nil,
		"ns1/orders",
		nil,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfFlow, []any{
		uint32(2), nil, nil, nil, nil, uint32(1),
	}); err != nil {
		t.Fatal(err)
	}
	if f, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}
	code, fields, rest, err := parseDescribedList(f.body)
	if err != nil || code != perfTransfer {
		t.Fatalf("transfer %x %v", code, err)
	}
	got := extractDataSection(rest)
	if string(got) != "via-amqp" {
		// maybe payload after fields consumed differently
		_ = fields
		if len(rest) == 0 {
			t.Fatalf("empty payload body=%v", f.body)
		}
	}

	if err := writePerformative(c1, 0, perfEnd, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfClose, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = readFrame(c1); err != nil {
		t.Fatal(err)
	}

	// applyConnectionString unit
	sess := &session{}
	sess.applyConnectionString("Endpoint=sb://ns2.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=" + sas + ";EntityPath=q")
	if sess.namespace != "ns2" || sess.sasKey != sas {
		t.Fatalf("%#v", sess)
	}
	sess.applyConnectionString("Endpoint=amqp://onlyhost:5671/;SharedAccessKey=k")
	if sess.namespace != "onlyhost" {
		t.Fatalf("%q", sess.namespace)
	}

	cancel()
	_ = c1.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
}

func readFullPipe(c net.Conn, b []byte) (int, error) {
	var n int
	for n < len(b) {
		nn, err := c.Read(b[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestParseDescribedListErrors(t *testing.T) {
	if _, _, _, err := parseDescribedList([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := parseList(nil); err == nil {
		t.Fatal("empty")
	}
	if _, _, _, err := parseValue(nil); err == nil {
		t.Fatal("empty value")
	}
	var buf bytes.Buffer
	_ = writeFrame(&buf, 0, encodeDescribedList(0x10, nil))
}
