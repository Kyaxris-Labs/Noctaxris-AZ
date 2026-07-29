// Package amqp implements AMQP 1.0 LITE for Service Bus lab queues.
//
// Full Azure azservicebus SDK interop is best-effort lite: this server speaks
// enough Open/Begin/Attach/Transfer/Flow/Disposition framing for simple custom
// clients and store-backed send/receive. CBS auth, sessions, and full link
// settlement semantics are not guaranteed.
package amqp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

var protocolHeader = []byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}

const (
	perfOpen         = 0x10
	perfBegin        = 0x11
	perfAttach       = 0x12
	perfFlow         = 0x13
	perfTransfer     = 0x14
	perfDisposition  = 0x15
	perfDetach       = 0x16
	perfEnd          = 0x17
	perfClose        = 0x18
)

// Start listens for AMQP 1.0 lite connections until ctx is cancelled.
func Start(ctx context.Context, addr string, st *store.Store) error {
	if addr == "" {
		addr = "127.0.0.1:5672"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("amqp listen %s: %w", addr, err)
	}

	var (
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
		wg    sync.WaitGroup
	)
	closeAll := func() {
		_ = ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}

	go func() {
		<-ctx.Done()
		closeAll()
	}()

	defer func() {
		closeAll()
		wg.Wait()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("amqp accept: %w", err)
			}
		}
		mu.Lock()
		conns[conn] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() {
				_ = c.Close()
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
			}()
			_ = handleConn(ctx, c, st)
		}(conn)
	}
}

func handleConn(ctx context.Context, c net.Conn, st *store.Store) error {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if string(hdr[:4]) != "AMQP" {
		return fmt.Errorf("bad protocol header")
	}
	if _, err := c.Write(protocolHeader); err != nil {
		return err
	}

	sess := &session{
		store:     st,
		namespace: "",
		links:     map[uint32]*link{},
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_ = c.SetDeadline(time.Now().Add(60 * time.Second))
		frame, err := readFrame(c)
		if err != nil {
			return err
		}
		if err := sess.onFrame(c, frame); err != nil {
			return err
		}
	}
}

type frame struct {
	channel uint16
	body    []byte
	payload []byte
}

type link struct {
	name      string
	handle    uint32
	role      bool // true = receiver (server receives = client sends)
	queue     string
	namespace string
	credit    uint32
}

type session struct {
	store     *store.Store
	namespace string
	sasKey    string
	links     map[uint32]*link
	nextDelivery uint32
}

func (s *session) onFrame(c net.Conn, f frame) error {
	if len(f.body) == 0 {
		return nil
	}
	code, fields, rest, err := parseDescribedList(f.body)
	if err != nil {
		return err
	}
	f.payload = rest
	switch code {
	case perfOpen:
		hostname := fieldString(fields, 1)
		s.namespace = trimSBHost(hostname)
		props := fieldMap(fields, 4)
		if cs, ok := props["connection-string"]; ok {
			s.applyConnectionString(cs)
		}
		if key, ok := props["SharedAccessKey"]; ok {
			s.sasKey = key
		}
		if name, ok := props["SharedAccessKeyName"]; ok {
			_ = name
		}
		return writePerformative(c, f.channel, perfOpen, []any{
			"noctaxris-az", // container-id
			nil,            // hostname
			uint32(65536),  // max-frame-size
			uint16(1),      // channel-max
		})
	case perfBegin:
		return writePerformative(c, f.channel, perfBegin, []any{
			uint16(0),     // remote-channel
			uint32(0),     // next-outgoing-id
			uint32(2048),  // incoming-window
			uint32(2048),  // outgoing-window
		})
	case perfAttach:
		name := fieldString(fields, 0)
		handle := fieldUint32(fields, 1)
		role := fieldBool(fields, 2) // false=sender, true=receiver (AMQP roles from peer perspective)
		// Peer role false = peer is sender = we receive transfers into store.
		queue := ""
		if tgt := fieldString(fields, 5); tgt != "" {
			queue = tgt
		}
		if src := fieldString(fields, 4); queue == "" && src != "" {
			queue = src
		}
		if queue == "" {
			queue = name
		}
		queue = strings.TrimPrefix(queue, "/")
		ns := s.namespace
		if i := strings.IndexByte(queue, '/'); i > 0 {
			ns = queue[:i]
			queue = queue[i+1:]
		}
		if s.sasKey != "" && ns != "" {
			want, ok, err := s.store.GetSBNamespaceKey(ns)
			if err == nil && ok && want != s.sasKey {
				return fmt.Errorf("sas key mismatch")
			}
		}
		s.links[handle] = &link{
			name:      name,
			handle:    handle,
			role:      !role, // our complementary role
			queue:     queue,
			namespace: ns,
		}
		// Echo attach with flipped role.
		return writePerformative(c, f.channel, perfAttach, []any{
			name,
			handle,
			!role,
			nil, // snd-settle-mode
			nil, // rcv-settle-mode
			queue,
			queue,
		})
	case perfFlow:
		handle := fieldUint32(fields, 0)
		credit := fieldUint32(fields, 5)
		lnk := s.links[handle]
		if lnk == nil {
			return nil
		}
		lnk.credit = credit
		// If peer is receiver (we are sender), deliver queued messages.
		if !lnk.role && credit > 0 {
			return s.deliver(c, f.channel, lnk)
		}
		return nil
	case perfTransfer:
		handle := fieldUint32(fields, 0)
		lnk := s.links[handle]
		if lnk == nil {
			return nil
		}
		body := extractDataSection(f.payload)
		if len(body) == 0 {
			body = f.payload
		}
		ns := lnk.namespace
		if ns == "" {
			ns = s.namespace
		}
		if err := s.store.EnqueueSB(ns, lnk.queue, body); err != nil {
			return err
		}
		deliveryID := fieldUint32(fields, 1)
		return writePerformative(c, f.channel, perfDisposition, []any{
			true, // role=receiver
			deliveryID,
			deliveryID,
			true, // settled
		})
	case perfDisposition:
		return nil
	case perfDetach:
		handle := fieldUint32(fields, 0)
		delete(s.links, handle)
		return writePerformative(c, f.channel, perfDetach, []any{handle, true})
	case perfEnd:
		return writePerformative(c, f.channel, perfEnd, nil)
	case perfClose:
		return writePerformative(c, f.channel, perfClose, nil)
	default:
		return nil
	}
}

func (s *session) deliver(c net.Conn, channel uint16, lnk *link) error {
	ns := lnk.namespace
	if ns == "" {
		ns = s.namespace
	}
	for lnk.credit > 0 {
		body, ok, err := s.store.DequeueSB(ns, lnk.queue)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		s.nextDelivery++
		deliveryID := s.nextDelivery
		payload := encodeDataSection(body)
		if err := writeTransfer(c, channel, lnk.handle, deliveryID, payload); err != nil {
			return err
		}
		lnk.credit--
	}
	return nil
}

func (s *session) applyConnectionString(cs string) {
	parts := strings.Split(cs, ";")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		switch strings.ToLower(k) {
		case "endpoint":
			v = strings.TrimPrefix(v, "sb://")
			v = strings.TrimPrefix(v, "amqp://")
			v = strings.TrimPrefix(v, "amqps://")
			v = strings.TrimSuffix(v, "/")
			if i := strings.IndexByte(v, '.'); i > 0 {
				s.namespace = v[:i]
			} else if i := strings.IndexByte(v, ':'); i > 0 {
				s.namespace = v[:i]
			} else {
				s.namespace = v
			}
		case "sharedaccesskey":
			s.sasKey = v
		case "sharedaccesskeyname":
			// accepted; RootManageSharedAccessKey theatre
		case "entitypath":
			// optional default queue; ignored at open
		}
	}
}

func trimSBHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "sb://")
	host = strings.TrimSuffix(host, "/")
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i]
	}
	if i := strings.IndexByte(host, ':'); i > 0 {
		return host[:i]
	}
	return host
}

func readFrame(r io.Reader) (frame, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return frame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[0:4])
	if size < 8 {
		return frame{}, fmt.Errorf("frame too small: %d", size)
	}
	doff := int(hdr[4]) * 4
	if doff < 8 || uint32(doff) > size {
		return frame{}, fmt.Errorf("bad doff")
	}
	channel := binary.BigEndian.Uint16(hdr[6:8])
	rest := make([]byte, size-8)
	if _, err := io.ReadFull(r, rest); err != nil {
		return frame{}, err
	}
	ext := doff - 8
	body := rest[ext:]
	return frame{channel: channel, body: body}, nil
}

func writeFrame(w io.Writer, channel uint16, body []byte) error {
	doff := 2
	size := 8 + len(body)
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(size))
	buf[4] = byte(doff)
	buf[5] = 0 // AMQP frame
	binary.BigEndian.PutUint16(buf[6:8], channel)
	copy(buf[8:], body)
	_, err := w.Write(buf)
	return err
}

func writePerformative(w io.Writer, channel uint16, code byte, fields []any) error {
	body := encodeDescribedList(code, fields)
	return writeFrame(w, channel, body)
}

func writeTransfer(w io.Writer, channel uint16, handle, deliveryID uint32, payload []byte) error {
	body := encodeDescribedList(perfTransfer, []any{
		handle,
		deliveryID,
		[]byte{1}, // delivery-tag
		nil,       // message-format
		true,      // settled
		false,     // more
	})
	body = append(body, payload...)
	return writeFrame(w, channel, body)
}

func encodeDescribedList(code byte, fields []any) []byte {
	list := encodeList(fields)
	out := []byte{0x00, 0x53, code}
	return append(out, list...)
}

func encodeList(fields []any) []byte {
	if len(fields) == 0 {
		return []byte{0x45} // empty list
	}
	var inner []byte
	for _, f := range fields {
		inner = append(inner, encodeValue(f)...)
	}
	if len(inner)+1 < 256 && len(fields) < 256 {
		out := make([]byte, 0, 3+len(inner))
		out = append(out, 0xc0, byte(len(inner)+1), byte(len(fields)))
		out = append(out, inner...)
		return out
	}
	out := make([]byte, 0, 9+len(inner))
	out = append(out, 0xd0)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(inner)+4))
	out = append(out, tmp...)
	binary.BigEndian.PutUint32(tmp, uint32(len(fields)))
	out = append(out, tmp...)
	out = append(out, inner...)
	return out
}

func encodeValue(v any) []byte {
	if v == nil {
		return []byte{0x40}
	}
	switch t := v.(type) {
	case bool:
		if t {
			return []byte{0x41}
		}
		return []byte{0x42}
	case uint16:
		return []byte{0x60, byte(t >> 8), byte(t)}
	case uint32:
		b := []byte{0x70, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], t)
		return b
	case string:
		sb := []byte(t)
		if len(sb) < 256 {
			out := make([]byte, 0, 2+len(sb))
			out = append(out, 0xa1, byte(len(sb)))
			out = append(out, sb...)
			return out
		}
		out := make([]byte, 0, 5+len(sb))
		out = append(out, 0xb1)
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, uint32(len(sb)))
		out = append(out, tmp...)
		out = append(out, sb...)
		return out
	case []byte:
		if len(t) < 256 {
			out := make([]byte, 0, 2+len(t))
			out = append(out, 0xa0, byte(len(t)))
			out = append(out, t...)
			return out
		}
		out := make([]byte, 0, 5+len(t))
		out = append(out, 0xb0)
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, uint32(len(t)))
		out = append(out, tmp...)
		out = append(out, t...)
		return out
	default:
		return []byte{0x40}
	}
}

func encodeDataSection(data []byte) []byte {
	// described type: descriptor 0x75 (data) + binary
	out := []byte{0x00, 0x53, 0x75}
	out = append(out, encodeValue(data)...)
	return out
}

func extractDataSection(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	// described data: 0x00 0x53 0x75 <binary>
	if len(payload) >= 3 && payload[0] == 0x00 && payload[1] == 0x53 && payload[2] == 0x75 {
		v, _, _, err := parseValue(payload[3:])
		if err == nil {
			if b, ok := v.([]byte); ok {
				return b
			}
			if s, ok := v.(string); ok {
				return []byte(s)
			}
		}
	}
	// bare binary
	v, _, _, err := parseValue(payload)
	if err == nil {
		if b, ok := v.([]byte); ok {
			return b
		}
		if s, ok := v.(string); ok {
			return []byte(s)
		}
	}
	return payload
}

func parseDescribedList(b []byte) (code byte, fields []any, rest []byte, err error) {
	if len(b) < 3 || b[0] != 0x00 {
		return 0, nil, nil, fmt.Errorf("not described")
	}
	i := 1
	switch b[i] {
	case 0x53:
		if len(b) < 3 {
			return 0, nil, nil, fmt.Errorf("short descriptor")
		}
		code = b[i+1]
		i += 2
	case 0x80:
		if len(b) < 10 {
			return 0, nil, nil, fmt.Errorf("short ulong descriptor")
		}
		code = b[i+8] // low byte of ulong
		i += 9
	default:
		return 0, nil, nil, fmt.Errorf("unsupported descriptor constructor %x", b[i])
	}
	fields, n, err := parseList(b[i:])
	if err != nil {
		return 0, nil, nil, err
	}
	return code, fields, b[i+n:], nil
}

func parseList(b []byte) ([]any, int, error) {
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("empty list")
	}
	switch b[0] {
	case 0x45:
		return nil, 1, nil
	case 0xc0:
		if len(b) < 3 {
			return nil, 0, fmt.Errorf("short list8")
		}
		size := int(b[1])
		count := int(b[2])
		if len(b) < 2+size {
			return nil, 0, fmt.Errorf("truncated list8")
		}
		items, _, err := parseListItems(b[3:2+size], count)
		return items, 2 + size, err
	case 0xd0:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("short list32")
		}
		size := int(binary.BigEndian.Uint32(b[1:5]))
		count := int(binary.BigEndian.Uint32(b[5:9]))
		if len(b) < 5+size {
			return nil, 0, fmt.Errorf("truncated list32")
		}
		items, _, err := parseListItems(b[9:5+size], count)
		return items, 5 + size, err
	default:
		// single value treated as one-field list
		v, n, _, err := parseValue(b)
		if err != nil {
			return nil, 0, err
		}
		return []any{v}, n, nil
	}
}

func parseListItems(b []byte, count int) ([]any, int, error) {
	fields := make([]any, 0, count)
	off := 0
	for i := 0; i < count; i++ {
		if off >= len(b) {
			fields = append(fields, nil)
			continue
		}
		v, n, _, err := parseValue(b[off:])
		if err != nil {
			return nil, 0, err
		}
		fields = append(fields, v)
		off += n
	}
	return fields, off, nil
}

func parseValue(b []byte) (any, int, []byte, error) {
	if len(b) == 0 {
		return nil, 0, nil, fmt.Errorf("empty value")
	}
	switch b[0] {
	case 0x40:
		return nil, 1, b[1:], nil
	case 0x41:
		return true, 1, b[1:], nil
	case 0x42:
		return false, 1, b[1:], nil
	case 0x43:
		return uint32(0), 1, b[1:], nil
	case 0x44:
		return uint64(0), 1, b[1:], nil
	case 0x50:
		if len(b) < 2 {
			return nil, 0, nil, fmt.Errorf("short ubyte")
		}
		return uint32(b[1]), 2, b[2:], nil
	case 0x52:
		if len(b) < 2 {
			return nil, 0, nil, fmt.Errorf("short uint0")
		}
		return uint32(b[1]), 2, b[2:], nil
	case 0x60:
		if len(b) < 3 {
			return nil, 0, nil, fmt.Errorf("short ushort")
		}
		return uint32(binary.BigEndian.Uint16(b[1:3])), 3, b[3:], nil
	case 0x70:
		if len(b) < 5 {
			return nil, 0, nil, fmt.Errorf("short uint")
		}
		return binary.BigEndian.Uint32(b[1:5]), 5, b[5:], nil
	case 0xa0:
		if len(b) < 2 {
			return nil, 0, nil, fmt.Errorf("short bin8")
		}
		n := int(b[1])
		if len(b) < 2+n {
			return nil, 0, nil, fmt.Errorf("trunc bin8")
		}
		out := make([]byte, n)
		copy(out, b[2:2+n])
		return out, 2 + n, b[2+n:], nil
	case 0xa1:
		if len(b) < 2 {
			return nil, 0, nil, fmt.Errorf("short str8")
		}
		n := int(b[1])
		if len(b) < 2+n {
			return nil, 0, nil, fmt.Errorf("trunc str8")
		}
		return string(b[2 : 2+n]), 2 + n, b[2+n:], nil
	case 0xb0:
		if len(b) < 5 {
			return nil, 0, nil, fmt.Errorf("short bin32")
		}
		n := int(binary.BigEndian.Uint32(b[1:5]))
		if len(b) < 5+n {
			return nil, 0, nil, fmt.Errorf("trunc bin32")
		}
		out := make([]byte, n)
		copy(out, b[5:5+n])
		return out, 5 + n, b[5+n:], nil
	case 0xb1:
		if len(b) < 5 {
			return nil, 0, nil, fmt.Errorf("short str32")
		}
		n := int(binary.BigEndian.Uint32(b[1:5]))
		if len(b) < 5+n {
			return nil, 0, nil, fmt.Errorf("trunc str32")
		}
		return string(b[5 : 5+n]), 5 + n, b[5+n:], nil
	case 0xc1, 0xd1: // map
		m, n, err := parseMap(b)
		if err != nil {
			return nil, 0, nil, err
		}
		return m, n, b[n:], nil
	case 0x00: // nested described — skip as opaque string of target/source
		code, fields, rest, err := parseDescribedList(b)
		if err != nil {
			return nil, 0, nil, err
		}
		_ = code
		// Source/Target often have address at fields[0]
		if len(fields) > 0 {
			if s, ok := fields[0].(string); ok {
				return s, len(b) - len(rest), rest, nil
			}
		}
		return nil, len(b) - len(rest), rest, nil
	default:
		// skip unknown single-byte constructor by treating remaining as opaque
		return nil, 1, b[1:], nil
	}
}

func parseMap(b []byte) (map[string]string, int, error) {
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("empty map")
	}
	var size, count, hdr int
	switch b[0] {
	case 0xc1:
		if len(b) < 3 {
			return nil, 0, fmt.Errorf("short map8")
		}
		size = int(b[1])
		count = int(b[2])
		hdr = 3
	case 0xd1:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("short map32")
		}
		size = int(binary.BigEndian.Uint32(b[1:5]))
		count = int(binary.BigEndian.Uint32(b[5:9]))
		hdr = 9
	default:
		return nil, 0, fmt.Errorf("not a map")
	}
	end := hdr - 1 + size
	if b[0] == 0xc1 {
		end = 2 + size
	} else {
		end = 5 + size
	}
	if end > len(b) {
		return nil, 0, fmt.Errorf("trunc map")
	}
	m := map[string]string{}
	off := hdr
	for i := 0; i+1 < count; i += 2 {
		k, n, _, err := parseValue(b[off:end])
		if err != nil {
			break
		}
		off += n
		v, n2, _, err := parseValue(b[off:end])
		if err != nil {
			break
		}
		off += n2
		ks, _ := k.(string)
		switch t := v.(type) {
		case string:
			m[ks] = t
		case []byte:
			m[ks] = string(t)
		}
	}
	return m, end, nil
}

func fieldString(fields []any, i int) string {
	if i >= len(fields) || fields[i] == nil {
		return ""
	}
	switch t := fields[i].(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}

func fieldUint32(fields []any, i int) uint32 {
	if i >= len(fields) || fields[i] == nil {
		return 0
	}
	switch t := fields[i].(type) {
	case uint32:
		return t
	case uint64:
		return uint32(t)
	case int:
		return uint32(t)
	default:
		return 0
	}
}

func fieldBool(fields []any, i int) bool {
	if i >= len(fields) || fields[i] == nil {
		return false
	}
	t, _ := fields[i].(bool)
	return t
}

func fieldMap(fields []any, i int) map[string]string {
	if i >= len(fields) || fields[i] == nil {
		return nil
	}
	m, _ := fields[i].(map[string]string)
	return m
}
