// Command greeter-caller calls greeter-app through heain.App.Call and prints
// one line per call: CALL <name> status=<n> [code=<c>] [out=<json>].
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
	defer app.Close(context.Background())
	wctx, cancel := context.WithTimeout(ctx, *wait)
	if err := app.WaitActive(wctx); err != nil {
		cli.Fail("wait", err)
	}
	cancel()
	fmt.Println("ACTIVE")

	call := func(ctx context.Context, name, capability, method, path string, body any) {
		var out map[string]any
		st, err := app.Call(ctx, heain.CallSpec{App: "greeter-app", Capability: capability, Method: method, Path: path, Body: body, Out: &out})
		line := fmt.Sprintf("CALL %s status=%d", name, st)
		var ce *heain.CallError
		switch {
		case errors.As(err, &ce):
			line += " code=" + ce.Code
		case errors.Is(err, heain.ErrNotDeclared):
			line += " code=not_declared"
		case err != nil:
			line += " err=" + err.Error()
		}
		if out != nil {
			raw, _ := json.Marshal(out)
			line += " out=" + string(raw)
		}
		fmt.Println(line)
	}
	bg := context.Background()
	call(bg, "hello", "greet.hello", "POST", "/v1/hello", map[string]any{"name": "ann"})
	call(bg, "hello-get", "greet.hello", "GET", "/v1/hello/bob", nil)
	call(bg, "tone", "greet.tone", "POST", "/v1/tone", map[string]any{"text": "great news!!"})
	call(bg, "tone-unrecorded", "greet.tone", "POST", "/v1/tone-unrecorded", map[string]any{"text": "hi"})
	inID := heain.WithTrace(bg, "", "identity")
	call(inID, "id", "greet.id", "POST", "/v1/id", nil)
	call(inID, "ballot", "greet.ballot", "POST", "/v1/ballot", nil)
	_, err := app.Call(bg, heain.CallSpec{App: "other-app", Capability: "x.y", Method: "POST", Path: "/x"})
	fmt.Printf("CALL undeclared notdeclared=%v\n", errors.Is(err, heain.ErrNotDeclared))
	fmt.Println("DONE")
}
