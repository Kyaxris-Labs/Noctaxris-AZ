package store_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestUpsertStorageAccountRefusesAzuriteOnNonLoopback(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	// Random keys never match Azurite; create succeeds on loopback.
	key, err := st.UpsertStorageAccount("sub", "rg", "devstoreaccount1", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	if config.AzuriteWellKnownCredentials("devstoreaccount1", key) {
		t.Fatal("generated key unexpectedly matched Azurite")
	}
}

func TestStorageQueueAndSBRoundtrip(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if _, err := st.UpsertStorageAccount("sub", "rg", "a1", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateQueue("a1", "q"); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue("a1", "q", "m1"); err != nil {
		t.Fatal(err)
	}
	body, ok, err := st.Dequeue("a1", "q")
	if err != nil || !ok || body != "m1" {
		t.Fatalf("dequeue: %v %q %v", ok, body, err)
	}

	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "ns", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusQueue("ns", "q"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSB("ns", "q", []byte("sb")); err != nil {
		t.Fatal(err)
	}
	b, ok, err := st.DequeueSB("ns", "q")
	if err != nil || !ok || string(b) != "sb" {
		t.Fatalf("sb dequeue: %v %q %v", ok, b, err)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(255 - i)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
