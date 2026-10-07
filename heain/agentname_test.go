package heain

import (
	"testing"

	"github.com/heainframework/heain-sdk/manifest"
)

func TestCheckSDKAcceptsAgent(t *testing.T) {
	var m manifest.Manifest
	for name, ok := range map[string]bool{SDKName: true, AgentName: true, "other": false} {
		m.App.SDK.Name, m.App.SDK.Version = name, ">=1.0.0"
		if err := checkSDK(m); (err == nil) != ok {
			t.Fatalf("%s: %v", name, err)
		}
	}
	m.App.SDK.Name, m.App.SDK.Version = AgentName, ">=2.0.0"
	if checkSDK(m) == nil {
		t.Fatal("agent version range")
	}
}
