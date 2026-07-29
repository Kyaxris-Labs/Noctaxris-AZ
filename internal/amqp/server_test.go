package amqp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/amqp"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestListenAcceptAndStoreEnqueueDequeue(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "ns1", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusQueue("ns1", "orders"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSB("ns1", "orders", []byte("amqp-payload")); err != nil {
		t.Fatal(err)
	}
	body, ok, err := st.DequeueSB("ns1", "orders")
	if err != nil || !ok || string(body) != "amqp-payload" {
		t.Fatalf("store roundtrip: ok=%v body=%q err=%v", ok, body, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- amqp.Start(ctx, addr, st)
	}()

	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Protocol header exchange proves Accept works.
	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 8)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFull(conn, hdr); err != nil {
		t.Fatal(err)
	}
	if string(hdr[:4]) != "AMQP" {
		t.Fatalf("header %v", hdr)
	}
	_ = conn.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not exit")
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		nn, err := c.Read(b[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 9)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
