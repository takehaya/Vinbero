package cplane

import "testing"

func TestExampleScopeAllowsWithdrawal(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatal("setup")
	}
	src.emit("custom-behavior", customBehaviorRoute("192.0.2.0/24", "fd00:3::100"))
	waitDelivered(t, m, "custom-behavior")
	withdrawn := customBehaviorRoute("10.0.0.0/24", "")
	withdrawn.IsWithdraw = true
	src.emit("custom-behavior", withdrawn)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 0 {
		t.Fatalf("withdrawn route remains installed due to unrelated out-of-scope route: %v", sortedV4(ops))
	}
}

func TestExampleReceivePrefixes(t *testing.T) {
	m, src, ops := exampleManager(t, "10.1.99.1/16", "10.2.0.0/16")
	for _, prefix := range []string{"10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.0.0.0/7"} {
		src.emit("custom-behavior", customBehaviorRoute(prefix, "fd00:2::100"))
	}
	waitDelivered(t, m, "custom-behavior")
	if got := sortedV4(ops); len(got) != 2 || got[0] != "10.1.0.0/24" || got[1] != "10.2.0.0/24" {
		t.Fatalf("receive filter installed %v", got)
	}
}
