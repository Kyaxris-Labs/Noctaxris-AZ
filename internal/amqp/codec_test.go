package amqp

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeParseRoundtrip(t *testing.T) {
	fields := []any{
		nil,
		true,
		false,
		uint16(7),
		uint32(42),
		"hello",
		[]byte("bin"),
		123, // default -> null
	}
	enc := encodeDescribedList(0x10, fields)
	code, got, rest, err := parseDescribedList(enc)
	if err != nil || code != 0x10 || len(rest) != 0 {
		t.Fatalf("parse: code=%x rest=%d err=%v", code, len(rest), err)
	}
	if len(got) != len(fields) {
		t.Fatalf("len %d", len(got))
	}
	if got[1] != true || got[2] != false {
		t.Fatalf("bools %#v", got)
	}
	if fieldUint32(got, 4) != 42 {
		t.Fatal(fieldUint32(got, 4))
	}
	if fieldString(got, 5) != "hello" {
		t.Fatal(fieldString(got, 5))
	}
	if !fieldBool(got, 1) || fieldBool(got, 2) {
		t.Fatal("fieldBool")
	}
	if fieldMap(got, 0) != nil {
		t.Fatal("fieldMap nil")
	}
	if fieldString(nil, 0) != "" || fieldUint32(nil, 0) != 0 || fieldBool([]any{nil}, 0) {
		t.Fatal("empty field helpers")
	}

	empty := encodeList(nil)
	items, n, err := parseList(empty)
	if err != nil || n != 1 || items != nil {
		t.Fatalf("empty list: %v %d %v", items, n, err)
	}

	longStr := strings.Repeat("x", 300)
	longBin := bytes.Repeat([]byte("y"), 300)
	big := encodeList([]any{longStr, longBin, uint32(1)})
	items, _, err = parseList(big)
	if err != nil || len(items) != 3 {
		t.Fatalf("big: %v %v", items, err)
	}
	if items[0].(string) != longStr {
		t.Fatal("long str")
	}
	if !bytes.Equal(items[1].([]byte), longBin) {
		t.Fatal("long bin")
	}

	data := encodeDataSection([]byte("payload"))
	if !bytes.Equal(extractDataSection(data), []byte("payload")) {
		t.Fatal("extract described")
	}
	bare := encodeValue([]byte("bare"))
	if !bytes.Equal(extractDataSection(bare), []byte("bare")) {
		t.Fatal("extract bare")
	}
	if string(extractDataSection([]byte("raw"))) != "raw" {
		t.Fatal("extract fallback")
	}
	if extractDataSection(nil) != nil {
		t.Fatal("nil")
	}
}

func TestWriteReadFrameAndTransfer(t *testing.T) {
	var buf bytes.Buffer
	if err := writePerformative(&buf, 1, 0x10, []any{"hi", uint32(3)}); err != nil {
		t.Fatal(err)
	}
	f, err := readFrame(&buf)
	if err != nil || f.channel != 1 || len(f.body) == 0 {
		t.Fatalf("%+v %v", f, err)
	}
	code, fields, _, err := parseDescribedList(f.body)
	if err != nil || code != 0x10 || fieldString(fields, 0) != "hi" {
		t.Fatalf("%x %#v %v", code, fields, err)
	}

	buf.Reset()
	if err := writeTransfer(&buf, 2, 9, 11, encodeDataSection([]byte("m"))); err != nil {
		t.Fatal(err)
	}
	f, err = readFrame(&buf)
	if err != nil || f.channel != 2 {
		t.Fatal(err)
	}

	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 4, 2, 0, 0, 0})); err == nil {
		t.Fatal("frame too small")
	}
}

func TestTrimSBHostAndParseValueExtras(t *testing.T) {
	if got := trimSBHost("sb://myns.servicebus.windows.net/"); got != "myns" {
		t.Fatalf("%q", got)
	}
	if got := trimSBHost("host:5671"); got != "host" {
		t.Fatalf("%q", got)
	}
	if got := trimSBHost("plain"); got != "plain" {
		t.Fatalf("%q", got)
	}

	v, n, _, err := parseValue([]byte{0x43})
	if err != nil || v != uint32(0) || n != 1 {
		t.Fatal(err)
	}
	v, n, _, err = parseValue([]byte{0x44})
	if err != nil || v != uint64(0) || n != 1 {
		t.Fatal(err)
	}
	v, n, _, err = parseValue([]byte{0x50, 9})
	if err != nil || v != uint32(9) {
		t.Fatal(err)
	}
	v, n, _, err = parseValue([]byte{0x52, 8})
	if err != nil || v != uint32(8) {
		t.Fatal(err)
	}
	// map8: constructor, size, count, key, value
	mapBytes := []byte{0xc1, 0x0b, 0x02, 0xa1, 0x01, 'k', 0xa1, 0x01, 'v'}
	// size should be count byte + items; adjust: size=1+2+2= len from after size byte
	// format: 0xc1 size count items... where size includes count byte
	mapBytes = []byte{0xc1, 7, 2, 0xa1, 1, 'k', 0xa1, 1, 'v'}
	m, mn, err := parseMap(mapBytes)
	if err != nil || m["k"] != "v" || mn != len(mapBytes) {
		t.Fatalf("%v %d %v", m, mn, err)
	}
	mv, _, _, err := parseValue(mapBytes)
	if err != nil {
		t.Fatal(err)
	}
	if mv.(map[string]string)["k"] != "v" {
		t.Fatal(mv)
	}

	// ulong descriptor path
	ulongDesc := []byte{0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x45}
	code, fields, _, err := parseDescribedList(ulongDesc)
	if err != nil || code != 0x10 || fields != nil {
		t.Fatalf("%x %#v %v", code, fields, err)
	}

	if fieldUint32([]any{uint64(5)}, 0) != 5 {
		t.Fatal("uint64")
	}
	if fieldUint32([]any{int(6)}, 0) != 6 {
		t.Fatal("int")
	}
	if fieldString([]any{[]byte("x")}, 0) != "x" {
		t.Fatal("bytes string")
	}
}
