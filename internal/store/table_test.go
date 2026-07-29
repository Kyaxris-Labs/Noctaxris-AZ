package store_test

import "testing"

func TestTableCRUDAndQuery(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if err := st.CreateTable("a1", "t1"); err != nil {
		t.Fatal(err)
	}
	names, err := st.ListTables("a1")
	if err != nil || len(names) != 1 || names[0] != "t1" {
		t.Fatalf("list tables: %v %v", names, err)
	}

	etag, err := st.UpsertEntity("a1", "t1", "pk", "rk", map[string]any{"Name": "Ada", "City": "London"}, false)
	if err != nil || etag == "" {
		t.Fatalf("upsert: %q %v", etag, err)
	}
	ent, ok, err := st.GetEntity("a1", "t1", "pk", "rk")
	if err != nil || !ok || ent.Properties["Name"] != "Ada" {
		t.Fatalf("get: %#v %v %v", ent, ok, err)
	}

	_, err = st.UpsertEntity("a1", "t1", "pk", "rk", map[string]any{"Name": "Augusta"}, true)
	if err != nil {
		t.Fatal(err)
	}
	ent, ok, err = st.GetEntity("a1", "t1", "pk", "rk")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if ent.Properties["Name"] != "Augusta" || ent.Properties["City"] != "London" {
		t.Fatalf("merge retained City: %#v", ent.Properties)
	}

	_, err = st.UpsertEntity("a1", "t1", "pk", "r2", map[string]any{"Name": "Grace"}, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.QueryEntities("a1", "t1", "pk", "", nil, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("query top: %v %v", got, err)
	}

	ok, err = st.DeleteEntity("a1", "t1", "pk", "rk")
	if err != nil || !ok {
		t.Fatalf("delete entity: %v %v", ok, err)
	}
	if err := st.DeleteTable("a1", "t1"); err != nil {
		t.Fatal(err)
	}
	names, err = st.ListTables("a1")
	if err != nil || len(names) != 0 {
		t.Fatalf("after delete: %v %v", names, err)
	}
}

func TestBlobListDeleteAndQueuePeek(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if _, err := st.UpsertStorageAccount("sub", "rg", "a1", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateContainer("a1", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob("a1", "c1", "f.txt", []byte("x"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	containers, err := st.ListContainers("a1")
	if err != nil || len(containers) != 1 || containers[0] != "c1" {
		t.Fatalf("containers: %v %v", containers, err)
	}
	blobs, err := st.ListBlobs("a1", "c1")
	if err != nil || len(blobs) != 1 || blobs[0] != "f.txt" {
		t.Fatalf("blobs: %v %v", blobs, err)
	}
	ok, err := st.DeleteBlob("a1", "c1", "f.txt")
	if err != nil || !ok {
		t.Fatalf("delete blob: %v %v", ok, err)
	}
	if err := st.DeleteContainer("a1", "c1"); err != nil {
		t.Fatal(err)
	}

	if err := st.CreateQueue("a1", "q"); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue("a1", "q", "m1"); err != nil {
		t.Fatal(err)
	}
	body, ok, err := st.Peek("a1", "q")
	if err != nil || !ok || body != "m1" {
		t.Fatalf("peek: %v %q %v", ok, body, err)
	}
	body, ok, err = st.Peek("a1", "q")
	if err != nil || !ok || body != "m1" {
		t.Fatalf("peek again: %v %q %v", ok, body, err)
	}
	body, ok, err = st.Dequeue("a1", "q", 60)
	if err != nil || !ok || body != "m1" {
		t.Fatalf("dequeue vis: %v %q %v", ok, body, err)
	}
	_, ok, err = st.Peek("a1", "q")
	if err != nil || ok {
		t.Fatalf("peek while hidden: ok=%v err=%v", ok, err)
	}
}
