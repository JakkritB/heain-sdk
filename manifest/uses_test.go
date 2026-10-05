package manifest

import "testing"

func TestUsesPatterns(t *testing.T) {
	m := Manifest{Uses: []Use{
		{App: "*", Capabilities: []string{"*.split", "*.merge", "*.unit"}},
		{App: "heain-audit", Capabilities: []string{"audit.append"}},
	}}
	cases := []struct {
		app, cap string
		want     bool
	}{
		{"heain-videos", "video.conform.split", true},
		{"heain-image", "image.resize.unit", true},
		{"heain-videos", "video.conform", false},
		{"heain-audit", "audit.append", true},
		{"heain-audit", "audit.read", false},
		{"other", "audit.append", false},
	}
	for _, c := range cases {
		if got := m.DependsOn(c.app, c.cap); got != c.want {
			t.Errorf("DependsOn(%s, %s) = %v, want %v", c.app, c.cap, got, c.want)
		}
	}
	if !m.UsesCapability("x.y.unit") || m.UsesCapability("x.y") {
		t.Fatal("UsesCapability")
	}
	for p, s := range map[string]string{"a*b*c": "aXbYc", "*": "anything", "heain-*": "heain-job", "*.split": "a.b.split"} {
		if !globMatch(p, s) {
			t.Errorf("%s should match %s", p, s)
		}
	}
	for p, s := range map[string]string{"a*b*c": "aXbY", "heain-*": "other", "*.split": "a.b.splitx"} {
		if globMatch(p, s) {
			t.Errorf("%s should not match %s", p, s)
		}
	}
}

func TestUsesValidation(t *testing.T) {
	base := func(u []Use) Manifest {
		f := false
		return Manifest{ManifestVersion: 1, App: AppInfo{ID: "abc", Version: "1.0.0", Group: "domain", API: "v1", SDK: SDKInfo{Name: "heain-sdk-go", Version: ">=1.0.0"}},
			Capabilities: []Capability{{Name: "a.b", Version: 1, Formal: &f, Execution: "job", AI: AIInfo{Used: &f}}}, Uses: u}
	}
	if err := Validate(base([]Use{{App: "*", Capabilities: []string{"*.split"}}})); err != nil {
		t.Fatalf("pattern refused: %v", err)
	}
	for _, u := range []Use{{App: "", Capabilities: []string{"x"}}, {App: "a b", Capabilities: []string{"x"}}, {App: "abc"}, {App: "abc", Capabilities: []string{"X/Y"}}} {
		if Validate(base([]Use{u})) == nil {
			t.Errorf("%+v accepted", u)
		}
	}
}
