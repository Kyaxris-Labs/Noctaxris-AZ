package managedidentity

import "testing"

func TestImdsMetadataHostVariants(t *testing.T) {
	cases := []struct {
		host string
		ok   bool
	}{
		{"169.254.169.254", true},
		{"169.254.169.254:80", true},
		{"METADATA", true},
		{"metadata.azure.com", true},
		{"Metadata.Azure.com:443", true},
		{"127.0.0.1", false},
		{"example.com", false},
		{"", false},
		{"  metadata  ", true},
	}
	for _, tc := range cases {
		if got := imdsMetadataHost(tc.host); got != tc.ok {
			t.Fatalf("imdsMetadataHost(%q)=%v want %v", tc.host, got, tc.ok)
		}
	}
}

func TestImdsPeerIPParsing(t *testing.T) {
	if ip := imdsPeerIP(""); ip != nil {
		t.Fatal("empty")
	}
	if ip := imdsPeerIP("127.0.0.1:9"); ip == nil || !ip.IsLoopback() {
		t.Fatalf("loopback %v", ip)
	}
	if ip := imdsPeerIP("169.254.1.2"); ip == nil || !ip.IsLinkLocalUnicast() {
		t.Fatalf("link local %v", ip)
	}
	if ip := imdsPeerIP("not-an-ip"); ip != nil {
		t.Fatal("garbage")
	}
}
