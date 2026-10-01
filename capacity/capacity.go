// Package capacity provides a shared, reusable live-resource probe (RAM
// via /proc/meminfo, GPU via nvidia-smi) and a single scoring function,
// for any Layer 3 module to expose over its own /capacity endpoint and
// for heain-job's Stage B scheduler to interpret consistently. This is a
// deliberate duplication of heain-core's own
// internal/protocol/dispatch.LinuxCapacityProbe (Go's internal package
// visibility rules block importing it across module boundaries) -- the
// same "duplicate across repos" convention already used for jobwire's
// wire types. Keeping the exact same probing mechanism (meminfo +
// nvidia-smi) across Layer 2's P2 dispatcher and every Layer 3 module's
// own self-reported capacity means a deployment only ever has to
// understand one capacity-probing mechanism, not two independently
// invented ones.
package capacity

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Capacity is a live snapshot of a replica's actual available resources
// at the moment it was probed. Field-for-field identical to heain-core's
// internal/protocol/dispatch.Capacity.
type Capacity struct {
	TotalMemoryBytes     uint64 `json:"total_memory_bytes"`
	AvailableMemoryBytes uint64 `json:"available_memory_bytes"`

	// HasGPU is false on a replica with no usable GPU (no nvidia-smi
	// binary found, or it returned an error) -- a normal, expected
	// outcome, not a probe failure.
	HasGPU              bool   `json:"has_gpu"`
	GPUTotalMemoryBytes uint64 `json:"gpu_total_memory_bytes"`
	GPUFreeMemoryBytes  uint64 `json:"gpu_free_memory_bytes"`
}

// Score reduces a Capacity snapshot to the single float64 headroom
// number heain-job's scheduler.CapacityHeadroom needs. GPU-bound work
// (e.g. heain-videos's video_restoration sidecar once GPU-accelerated)
// is dominated by GPU memory contention, not system RAM, so a replica
// reporting a usable GPU is scored on its GPU-free percentage alone; a
// replica with no GPU is scored on its system-RAM-available percentage
// instead. Both are 0-100 percentages, so scores from GPU and non-GPU
// replicas remain directly comparable to each other and to the
// scheduler's existing percent-remaining-load subtraction.
func (c Capacity) Score() float64 {
	if c.HasGPU && c.GPUTotalMemoryBytes > 0 {
		return float64(c.GPUFreeMemoryBytes) / float64(c.GPUTotalMemoryBytes) * 100
	}
	if c.TotalMemoryBytes == 0 {
		return 0
	}
	return float64(c.AvailableMemoryBytes) / float64(c.TotalMemoryBytes) * 100
}

// Probe is the pluggable interface a module's /capacity handler calls.
type Probe interface {
	Probe() (Capacity, error)
}

// LinuxProbe reads real RAM availability from /proc/meminfo and real
// GPU memory availability via nvidia-smi -- an exact duplicate of
// heain-core's LinuxCapacityProbe, kept in lockstep with it so every
// layer of the system measures capacity the same way.
type LinuxProbe struct {
	// MemInfoPath overrides the /proc/meminfo path, for tests. Empty
	// means the real path is used.
	MemInfoPath string
}

// NewLinuxProbe returns a LinuxProbe configured for real use.
func NewLinuxProbe() *LinuxProbe {
	return &LinuxProbe{}
}

func (p *LinuxProbe) Probe() (Capacity, error) {
	total, available, err := p.readMemInfo()
	if err != nil {
		return Capacity{}, fmt.Errorf("capacity: reading memory info: %w", err)
	}

	cap := Capacity{
		TotalMemoryBytes:     total,
		AvailableMemoryBytes: available,
	}

	gpuTotal, gpuFree, hasGPU := probeGPU()
	cap.HasGPU = hasGPU
	cap.GPUTotalMemoryBytes = gpuTotal
	cap.GPUFreeMemoryBytes = gpuFree

	return cap, nil
}

func (p *LinuxProbe) readMemInfo() (totalBytes, availableBytes uint64, err error) {
	path := p.MemInfoPath
	if path == "" {
		path = "/proc/meminfo"
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalBytes, err = parseMemInfoLineKB(line)
			if err != nil {
				return 0, 0, fmt.Errorf("parsing MemTotal: %w", err)
			}
		case strings.HasPrefix(line, "MemAvailable:"):
			availableBytes, err = parseMemInfoLineKB(line)
			if err != nil {
				return 0, 0, fmt.Errorf("parsing MemAvailable: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return totalBytes, availableBytes, nil
}

func parseMemInfoLineKB(line string) (uint64, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected line format: %q", line)
	}
	kb, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing value in %q: %w", line, err)
	}
	return kb * 1024, nil
}

func probeGPU() (totalBytes, freeBytes uint64, hasGPU bool) {
	out, err := exec.Command(
		"nvidia-smi",
		"--query-gpu=memory.total,memory.free",
		"--format=csv,noheader,nounits",
	).Output()
	if err != nil {
		return 0, 0, false
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			continue
		}
		totalMB, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
		freeMB, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		totalBytes += totalMB * 1024 * 1024
		freeBytes += freeMB * 1024 * 1024
		hasGPU = true
	}
	return totalBytes, freeBytes, hasGPU
}
