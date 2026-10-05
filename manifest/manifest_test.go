package manifest

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const base = `manifest_version: 1
app: {id: hello-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0 <2.0.0"}}
capabilities:
  - {name: hello.greet, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/greet, capability: hello.greet, formal: true}
`

func code(t *testing.T, y string) string {
	t.Helper()
	m, err := Parse([]byte(y), ".yaml")
	if err == nil {
		err = Validate(m)
	}
	var ve *ValidationError
	if err == nil {
		return ""
	}
	if !errors.As(err, &ve) {
		t.Fatalf("not a ValidationError: %v", err)
	}
	return ve.Code + ": " + strings.Join(ve.Reasons, "; ")
}

func TestYAMLAndJSONAreTheSameManifest(t *testing.T) {
	y, err := Load("testdata/hello.yaml")
	if err != nil {
		t.Fatal(err)
	}
	j, err := Load("testdata/hello.json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(y, j) {
		t.Fatalf("YAML and JSON differ:\n%+v\n%+v", y, j)
	}
	if err := Validate(y); err != nil {
		t.Fatal(err)
	}
	if err := CheckSDK(y, "heain-sdk-go", "1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func TestRules(t *testing.T) {
	cases := []struct{ name, edit, want string }{
		{"valid", "", ""},
		{"formal missing on capability", strings.Replace(base, "formal: true, execution", "execution", 1), "manifest_formal_missing"},
		{"formal missing on endpoint", strings.Replace(base, "capability: hello.greet, formal: true}", "capability: hello.greet}", 1), "manifest_formal_missing"},
		{"typo is refused, not ignored", strings.Replace(base, "formal: true, execution", "fromal: true, execution", 1), "manifest_invalid"},
		{"direct without endpoint", strings.Split(base, "endpoints:")[0], "has no endpoint"},
		{"ai.used true without model", strings.Replace(base, "ai: {used: false}", "ai: {used: true}", 1), "ai.model"},
		{"bad execution", strings.Replace(base, "execution: direct", "execution: push", 1), "execution must be"},
		{"bad app id", strings.Replace(base, "id: hello-app", "id: Hello_App", 1), "app.id"},
		{"unknown api", strings.Replace(base, "api: v1", "api: v9", 1), "api_unsupported"},
		{"endpoint to unknown capability", strings.Replace(base, "path: /v1/greet, capability: hello.greet", "path: /v1/greet, capability: nope", 1), "unknown capability"},
		{"undeclared lane in pair", base + "lanes: {unlinkable: [[identity, ballot]]}\n", "undeclared lane"},
		{"data class without sovereignty", base + "data_classes: [{name: d1}]\n", "sovereignty"},
		{"retention max below min", base + "data_classes: [{name: d1, sovereignty: zone-local, retention: {max: 1d, min: 2d}}]\n", "below retention.min"},
		{"persisted data not encrypted", base + "data_classes: [{name: d1, sovereignty: zone-local, encrypted_at_rest: false}]\n", "encrypted_at_rest"},
		{"offline lists unknown capability", base + "offline: {allowed: [nope]}\n", "offline.allowed"},
	}
	for _, c := range cases {
		got := code(t, c.edit)
		if base == c.edit {
			got = code(t, base)
		}
		if c.edit == "" {
			got = code(t, base)
		}
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSDKRange(t *testing.T) {
	for _, c := range []struct {
		v, r string
		ok   bool
	}{
		{"1.0.0", ">=1.0.0 <2.0.0", true},
		{"2.0.0", ">=1.0.0 <2.0.0", false},
		{"0.9.0", ">=1.0.0", false},
		{"1.2.3", "1.2.3", true},
		{"1.2.3", ">1.2.3", false},
	} {
		ok, err := SatisfiesRange(c.v, c.r)
		if err != nil || ok != c.ok {
			t.Errorf("%s in %q: %v %v", c.v, c.r, ok, err)
		}
	}
	m, _ := Parse([]byte(base), ".yaml")
	m.App.SDK.Name = "other-sdk"
	if CheckSDK(m, "heain-sdk-go", "1.0.0") == nil {
		t.Fatal("another SDK's manifest must be refused")
	}
}
