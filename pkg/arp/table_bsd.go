//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package arp

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Table returns the IPv4 neighbors of the kernel's table, from arp -an.
func Table() ([]Neighbor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "arp", "-an").Output()
	if err != nil {
		return nil, fmt.Errorf("reading the neighbor table, arp -an: %w", err)
	}
	return ParseBSD(string(output)), nil
}
