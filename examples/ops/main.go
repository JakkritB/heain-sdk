// Command ops drives the other SDK features from the command line, one
// line of output per step (used by the live tests):
//
//	ops -do job -cap text.upper -payload hello   JOB <ticket> state=<s> out=<output>
//	ops -do propose -type grant.extend -category ALLOWLIST_BASED
//	                                               PROPOSED <id> result=<r>, then DECIDED <id> result=<r>
//	ops -do broadcast -discovery d1 -zone zone-a   BROADCAST <id> result=<r>
//	ops -do journal -kind vote.counted -n 2        JOURNAL app_seq=<n> seq=<n> hlc=<h> (n times)
//	ops -do journal-status                         JOURNAL-STATUS state=<s> last=<n> acked=<n>
//	ops -do mode                                   MODE <mode>
//	ops -do watch -for 60s                         MODE <mode> on every change
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/examples/internal/cli"
	"github.com/heainframework/heain-sdk/heain"
)

func main() {
	f := cli.Register("heain-app.yaml")
	do := flag.String("do", "job", "job | propose | broadcast | journal | journal-status | mode | watch")
	capName := flag.String("cap", "text.upper", "job capability")
	payload := flag.String("payload", "hello", "job payload")
	ptype := flag.String("type", "grant.extend", "P5 action type")
	category := flag.String("category", heain.CategoryAllowlist, "P5 category")
	value := flag.Float64("value", 0, "P5 value")
	disc := flag.String("discovery", "d1", "P7 discovery id")
	zone := flag.String("zone", "zone-a", "origin zone")
	kind := flag.String("kind", "vote.counted", "journal event kind")
	n := flag.Int("n", 1, "journal events to write")
	dur := flag.Duration("for", 60*time.Second, "watch duration / wait limit")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app := f.Start(ctx, "")
	defer app.Close(context.Background())
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	if err := app.WaitActive(wctx); err != nil {
		cli.Fail("wait", err)
	}
	cancel()
	ctx, cancel = context.WithTimeout(ctx, *dur)
	defer cancel()
	fail := func(stage string, err error) {
		var ce *core.Error
		if errors.As(err, &ce) {
			fmt.Printf("ERROR stage=%s code=%s\n", stage, ce.Code)
		} else {
			fmt.Printf("ERROR stage=%s err=%v\n", stage, err)
		}
		_ = app.Close(context.Background())
		os.Exit(1)
	}
	switch *do {
	case "job":
		t, err := app.Submit(ctx, heain.JobRequest{Capability: *capName, Payload: []byte(*payload)})
		if err != nil {
			fail("submit", err)
		}
		s, err := app.WaitJob(ctx, t.TicketID)
		if err != nil {
			fail("wait", err)
		}
		fmt.Printf("JOB %s state=%s attempts=%d out=%s\n", t.TicketID, s.State, s.Attempts, s.Output)
	case "propose":
		r, err := app.Propose(ctx, heain.Proposal{Type: *ptype, Category: *category, Value: *value, ZoneID: *zone})
		if err != nil {
			fail("propose", err)
		}
		fmt.Printf("PROPOSED %s result=%s\n", r.ActionID, r.Result)
		if r, err = app.WaitPolicy(ctx, r.ActionID); err != nil {
			fail("wait", err)
		}
		fmt.Printf("DECIDED %s result=%s\n", r.ActionID, r.Result)
	case "broadcast":
		r, err := app.Broadcast(ctx, *disc, *zone, map[string]any{"rule": "lighting-adjust", "customer_id": "c1"})
		if err != nil {
			fail("broadcast", err)
		}
		fmt.Printf("BROADCAST %s result=%s\n", r.ActionID, r.Result)
	case "journal":
		for i := 0; i < *n; i++ {
			e, err := app.Journal(ctx, *kind, "", map[string]any{"unit": "7", "i": i})
			if err != nil {
				fail("journal", err)
			}
			fmt.Printf("JOURNAL app_seq=%d seq=%d hlc=%s\n", e.AppSeq, e.Seq, e.HLC)
		}
	case "journal-status":
		s, err := app.JournalProgress(ctx)
		if err != nil {
			fail("journal-status", err)
		}
		fmt.Printf("JOURNAL-STATUS state=%s last=%d acked=%d\n", s.State, s.LastSeq, s.AckedThroughSeq)
	case "mode":
		m, err := app.FetchMode(ctx)
		if err != nil {
			fail("mode", err)
		}
		fmt.Printf("MODE %s\n", m.Mode)
	case "watch":
		m, _ := app.FetchMode(ctx)
		fmt.Printf("MODE %s\n", m.Mode)
		app.OnModeChange(func(_, cur heain.Mode) { fmt.Printf("MODE %s\n", cur.Mode) })
		<-ctx.Done()
	default:
		fail("flags", fmt.Errorf("unknown -do %q", *do))
	}
	fmt.Println("DONE")
}
