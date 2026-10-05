package conformance

import (
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Hold keeps a network namespace alive (the node's "pod": core, the app
// under test, the driver and the capture share it; restarting core does
// not take the others down).
func Hold() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	<-ch
}

// Proxy forwards TCP from listen to target while the state file does not
// say "cut" (C10: the driver cuts and heals the only path from W to G).
func Proxy(listen, target, stateFile string) {
	var mu sync.Mutex
	var ln net.Listener
	conns := map[net.Conn]bool{}
	up := func() {
		mu.Lock()
		defer mu.Unlock()
		if ln != nil {
			return
		}
		l, err := net.Listen("tcp", listen)
		if err != nil {
			log.Printf("proxy: listen: %v", err)
			return
		}
		ln = l
		log.Printf("proxy: up %s -> %s", listen, target)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					u, err := net.DialTimeout("tcp", target, 5*time.Second)
					if err != nil {
						c.Close()
						return
					}
					mu.Lock()
					conns[c], conns[u] = true, true
					mu.Unlock()
					go func() { _, _ = io.Copy(u, c); u.Close(); c.Close() }()
					_, _ = io.Copy(c, u)
					c.Close()
					u.Close()
					mu.Lock()
					delete(conns, c)
					delete(conns, u)
					mu.Unlock()
				}()
			}
		}()
	}
	cut := func() {
		mu.Lock()
		defer mu.Unlock()
		if ln == nil {
			return
		}
		ln.Close()
		ln = nil
		for c := range conns {
			c.Close()
		}
		conns = map[net.Conn]bool{}
		log.Printf("proxy: CUT")
	}
	for {
		b, _ := os.ReadFile(stateFile)
		if strings.TrimSpace(string(b)) == "cut" {
			cut()
		} else {
			up()
		}
		time.Sleep(200 * time.Millisecond)
	}
}
