package store

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
)

func TestEnsureRootDisplayNameDefaultAndStrip(t *testing.T) {
	key, err := LoadOrCreateMasterKey(t.TempDir() + "/master.key")
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(config.EnvStripProduct, "")
	st, err := Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sub := "11111111-1111-1111-1111-111111111111"
	tid := "22222222-2222-2222-2222-222222222222"
	if err := st.EnsureRoot(tid, sub, "root"); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListSubscriptions()
	if err != nil || len(list) == 0 {
		t.Fatalf("list %v %v", list, err)
	}
	if list[0]["displayName"] != "Noctaxris-AZ Lab" {
		t.Fatalf("default display %q", list[0]["displayName"])
	}

	t.Setenv(config.EnvStripProduct, "1")
	st2, err := Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.EnsureRoot(tid, sub, "root"); err != nil {
		t.Fatal(err)
	}
	list2, err := st2.ListSubscriptions()
	if err != nil || len(list2) == 0 {
		t.Fatalf("list2 %v %v", list2, err)
	}
	if list2[0]["displayName"] != "Lab" {
		t.Fatalf("strip display %q", list2[0]["displayName"])
	}
}
