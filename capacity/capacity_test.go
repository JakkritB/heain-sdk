package capacity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMemInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meminfo")
	content := "MemTotal:       32944704 kB\nMemFree:         1000000 kB\nMemAvailable:   20000000 kB\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	p := &LinuxProbe{MemInfoPath: path}
	total, avail, err := p.readMemInfo()
	if err != nil {
		t.Fatalf("readMemInfo failed: %v", err)
	}
	if total != 32944704*1024 {
		t.Errorf("total = %d, want %d", total, uint64(32944704*1024))
	}
	if avail != 20000000*1024 {
		t.Errorf("available = %d, want %d", avail, uint64(20000000*1024))
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		name string
		c    Capacity
		want float64
	}{
		{
			name: "no GPU, half RAM free",
			c:    Capacity{TotalMemoryBytes: 1000, AvailableMemoryBytes: 500},
			want: 50,
		},
		{
			name: "has GPU, RAM irrelevant, GPU mostly free",
			c:    Capacity{TotalMemoryBytes: 1000, AvailableMemoryBytes: 10, HasGPU: true, GPUTotalMemoryBytes: 1000, GPUFreeMemoryBytes: 900},
			want: 90,
		},
		{
			name: "zero total memory, no GPU",
			c:    Capacity{},
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.c.Score()
			if got != tc.want {
				t.Errorf("Score() = %v, want %v", got, tc.want)
			}
		})
	}
}
