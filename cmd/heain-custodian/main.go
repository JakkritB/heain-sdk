// heain-custodian: a custodian's part in opening sealed data (heain-core
// C12, heain-sdk 1.6). It reads the holder's shares of the keys a grant
// covers from a heain-core node, decrypts them with the holder's key on this
// machine, encrypts them again to that node for that grant, sends them, and
// approves the grant (-approve=false to send only).
//
//	heain-custodian -core https://node:8443 -server-name z-b1-1 \
//	  -cert org-a.pem -key org-a.key -ca ca.pem -grant <action id>
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/heainframework/heain-sdk/custody"
)

func main() {
	core := flag.String("core", "", "the heain-core node's admin URL")
	serverName := flag.String("server-name", "", "the node's name in its certificate")
	cert := flag.String("cert", "", "the holder's certificate (PEM)")
	key := flag.String("key", "", "the holder's key (PEM, RSA)")
	ca := flag.String("ca", "", "the CA the node's certificate chains to")
	grant := flag.String("grant", "", "the P5 grant (action id) to take part in")
	approve := flag.Bool("approve", true, "also approve the grant (the holder's P5 approval)")
	flag.Parse()
	if *core == "" || *serverName == "" || *cert == "" || *key == "" || *ca == "" || *grant == "" {
		flag.Usage()
		os.Exit(2)
	}
	c, err := custody.New(*core, *cert, *key, *ca, *serverName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := c.TakePart(ctx, *grant, *approve)
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
