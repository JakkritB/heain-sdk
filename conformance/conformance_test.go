package conformance

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The proxy between W and G must see plaintext even when it is split
// across reads (C13).
func TestScanProxyFindsSplitMarker(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	defer echo.Close()
	mf := filepath.Join(t.TempDir(), "markers.txt")
	_ = os.WriteFile(mf, []byte("top-secret-payload\n"), 0o644)
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := free.Addr().String()
	free.Close()
	p := newScanProxy(addr, echo.Addr().String(), mf)
	defer p.close()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("xx top-sec"))
	time.Sleep(50 * time.Millisecond)
	_, _ = c.Write([]byte("ret-payload yy"))
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := 0
	for got < 24 {
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		got += n
	}
	c.Close()
	time.Sleep(50 * time.Millisecond)
	if _, hits := p.stats(); hits["top-secret-payload"] == 0 {
		t.Fatalf("a marker split across reads was not seen: %v", hits)
	}
	p.cut()
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("a cut proxy must refuse connections")
	}
}

func TestReportStatus(t *testing.T) {
	r := &Report{}
	r.group("C2").add(Check{Name: "a", OK: true})
	r.group("C9").add(Check{Name: "b", OK: true, Skipped: true})
	if !r.Passed() || r.group("C9").Status != "n/a" {
		t.Fatalf("pass with a skip: %+v", r.Groups)
	}
	r.group("C2").add(Check{Name: "c", OK: false})
	if r.Passed() || r.group("C2").Status != "fail" {
		t.Fatal("a failed check fails its group and the run")
	}
	if r.Groups[0].ID != "C2" || r.Groups[1].ID != "C9" {
		t.Fatal("groups are ordered by number")
	}
}
