package main

import (
	"flag"
	"testing"
	"time"
)

func TestDeprecatedFlags(t *testing.T) {
	for old, current := range deprecatedFlags {
		if flag.Lookup(current) == nil {
			t.Errorf("-%s: no flag -%s", old, current)
		}
	}
	if err := flag.CommandLine.Parse([]string{"-ipv4-active=false", "-ipv4-lifetime=3m", "-exclude-interfaces=docker*", "-ipv6_listen=false"}); err != nil {
		t.Fatal(err)
	}
	if ipv4Active || ipv4Lifetime != 3*time.Minute || len(excludeInterfaces) != 1 || excludeInterfaces[0] != "docker*" || ipv6Listen {
		t.Errorf("got ipv4_active %v, ipv4_lifetime %s, exclude_interfaces %v, ipv6_listen %v", ipv4Active, ipv4Lifetime, excludeInterfaces, ipv6Listen)
	}
	if warnings := deprecatedFlagsGiven(); len(warnings) != 3 {
		t.Errorf("warnings: %v", warnings)
	}
}
