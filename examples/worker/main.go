// Command worker is the heain-sdk job worker example: it claims text.upper
// and text.tone jobs from the core on its node and runs them. The SDK
// leases, audits, enforces reasoning records and the offline rules.
//
// Test payloads: "corrupt" fails permanently; "flaky" fails once and then
// succeeds (core retries it).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/examples/internal/cli"
	"github.com/heainframework/heain-sdk/heain"
)

func main() {
	f := cli.Register("heain-app.yaml")
	wait := flag.Duration("wait-active", 60*time.Second, "how long to wait for admission")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app := f.Start(ctx, "")
	wctx, cancel := context.WithTimeout(ctx, *wait)
	if err := app.WaitActive(wctx); err != nil {
		cli.Fail("wait", err)
	}
	cancel()
	fmt.Println("ACTIVE")
	app.OnModeChange(func(_, cur heain.Mode) { fmt.Printf("MODE %s\n", cur.Mode) })

	var mu sync.Mutex
	seen := map[string]int{}
	w := app.NewWorker()
	must := func(err error) {
		if err != nil {
			cli.Fail("handle", err)
		}
	}
	must(w.Handle("text.upper", func(ctx context.Context, j *heain.Job) ([]byte, error) {
		mu.Lock()
		seen[j.TicketID]++
		n := seen[j.TicketID]
		mu.Unlock()
		fmt.Printf("RAN %s text.upper attempt=%d\n", j.TicketID, n)
		switch string(j.Payload) {
		case "corrupt":
			return nil, heain.Permanent(fmt.Errorf("payload cannot be processed"))
		case "flaky":
			if n == 1 {
				return nil, fmt.Errorf("temporary failure")
			}
		}
		return []byte(strings.ToUpper(string(j.Payload))), nil
	}))
	must(w.Handle("text.tone", func(ctx context.Context, j *heain.Job) ([]byte, error) {
		fmt.Printf("RAN %s text.tone\n", j.TicketID)
		tone, conf := "calm", 0.7
		if strings.Count(string(j.Payload), "!") >= 2 {
			tone, conf = "loud", 0.9
		}
		if _, err := app.Reason(ctx, heain.Decision{Capability: "text.tone", Input: j.Payload, Decision: tone, Confidence: &conf,
			Summary: "counted exclamation marks", Role: "decision", Factors: []heain.Factor{{Name: "exclamations", Value: float64(strings.Count(string(j.Payload), "!"))}}}); err != nil {
			return nil, err
		}
		return []byte(tone), nil
	}))
	fmt.Println("WORKING")
	_ = w.Run(ctx)
	if err := app.Close(context.Background()); err != nil {
		cli.Fail("close", err)
	}
	fmt.Println("DEREGISTERED")
}
