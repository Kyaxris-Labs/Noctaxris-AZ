package amqp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestAttachWithoutSharedAccessKeyFails(t *testing.T) {
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 3)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "ns1", "eastus"); err != nil {
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
	if err := writePerformative(c1, 0, perfOpen, []any{
		"client", "ns1.servicebus.windows.net", uint32(65536), uint16(1), nil,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfBegin, []any{nil, uint32(0), uint32(100), uint32(100)}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfAttach, []any{
		"sender", uint32(1), false, nil, nil, "ns1/orders",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected attach failure without SharedAccessSignature")
		}
	case <-time.After(2 * time.Second):
		// peer may close without pushing err; try reading
		_ = c1.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := readFrame(c1); err == nil {
			t.Fatal("attach without SAS unexpectedly continued")
		}
	}
}

func TestAttachRejectsBareSharedAccessKey(t *testing.T) {
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 5)
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
	if err := writePerformative(c1, 0, perfOpen, []any{
		"client", "ns1.servicebus.windows.net", uint32(65536), uint16(1),
		map[string]string{"SharedAccessKey": sas},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfBegin, []any{nil, uint32(0), uint32(100), uint32(100)}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(c1); err != nil {
		t.Fatal(err)
	}
	if err := writePerformative(c1, 0, perfAttach, []any{
		"sender", uint32(1), false, nil, nil, "ns1/orders",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected attach failure for bare SharedAccessKey")
		}
	case <-time.After(2 * time.Second):
		_ = c1.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := readFrame(c1); err == nil {
			t.Fatal("bare SharedAccessKey attach unexpectedly continued")
		}
	}
}
