package bpf

import "testing"

// Every kernel the data plane is tested on accepts BPF_FIB_LOOKUP_TBID (the
// 6.1 stable kernel included), and the probe says so. Needs root.
func TestProbeFibLookupTBID(t *testing.T) {
	ok, err := ProbeFibLookupTBID()
	if err != nil {
		t.Fatalf("ProbeFibLookupTBID: %v", err)
	}
	if !ok {
		t.Error("ProbeFibLookupTBID = false on a kernel that accepts BPF_FIB_LOOKUP_TBID")
	}
}
