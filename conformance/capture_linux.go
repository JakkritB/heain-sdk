//go:build linux

package conformance

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Capture reads every frame on iface (AF_PACKET, needs CAP_NET_RAW) and
// counts frames carrying any marker listed in markersFile (one per line):
// plaintext that must never leave the node (C13). It writes its counts to
// out every 2 s.
func Capture(iface, markersFile, out string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return err
	}
	var mu sync.Mutex
	var markers [][]byte
	res := map[string]any{"iface": iface, "frames": 0, "bytes": 0, "hits": map[string]int{}}
	go func() {
		for {
			if b, err := os.ReadFile(markersFile); err == nil {
				var ms [][]byte
				for _, l := range strings.Split(string(b), "\n") {
					if l = strings.TrimSpace(l); len(l) >= 6 {
						ms = append(ms, []byte(l))
					}
				}
				mu.Lock()
				markers = ms
				res["markers"] = len(ms)
				_ = writeJSONFile(out, res)
				mu.Unlock()
			}
			time.Sleep(2 * time.Second)
		}
	}()
	buf := make([]byte, 65536)
	log.Printf("capture: listening on %s", iface)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		mu.Lock()
		res["frames"] = res["frames"].(int) + 1
		res["bytes"] = res["bytes"].(int) + n
		for _, m := range markers {
			if bytes.Contains(buf[:n], m) {
				res["hits"].(map[string]int)[string(m)]++
			}
		}
		mu.Unlock()
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
