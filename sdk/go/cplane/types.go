// Package cplane provides typed events, desired-set declarations and a BGP
// prefix-route view for control-plane plugins. It can run under TinyGo or in
// native Go tests. Package guest supplies the WASM entry points and host calls.
// Ownership, scope enforcement and map reconciliation belong to the daemon.
package cplane

type EventKind uint32

const (
	EventRoute         EventKind = 1
	EventMAC           EventKind = 2
	EventEndOfReplay   EventKind = 3
	EventLocalSID      EventKind = 5
	EventStartOfReplay EventKind = 6
	BGPSource                    = "bgp"
)

type Event struct {
	Kind         EventKind
	Sequence     uint64
	Route        Route
	MAC          MACEvent
	ReplaySource string
	LocalSID     LocalSIDAllocated
}

// Route owns its strings and bytes; they survive the host freeing its buffer.
type Route struct {
	Family            string
	Withdraw          bool
	Peer              string
	PathID            uint32
	EndpointBehavior  uint32
	RD                string
	Prefix            string
	SRv6SID           string
	NextHop           string
	RouteTargets      []string
	Color             uint32
	MAC               string
	IPAddr            string
	EthernetTag       uint32
	ESI               []byte
	UnknownAttributes []UnknownAttribute
}

type UnknownAttribute struct {
	Type  uint32
	Flags uint32
	Value []byte
}

type MACEvent struct {
	BDID  uint32
	MAC   string
	Added bool
}

type LocalSIDAllocated struct{ Name, SID, Locator string }

type Disposition uint32

const (
	Handled    Disposition = 1
	Quarantine Disposition = 2
)

type EventResult struct {
	Sequence    uint64
	Disposition Disposition
	Reason      string
}

type Kind uint32

const (
	HeadendV4 Kind = 1
	HeadendV6 Kind = 2
	Advertise Kind = 3
	LocalSIDs Kind = 4
)

type HeadendEntry struct {
	TriggerPrefix string
	Segments      []string
	SrcAddr       string
	Mode          uint32
}

// AdvertisedRoute names a VRF; the host derives RD and RT from its binding.
// SRv6SID must be a SID allocated to this plugin by the host.
type AdvertisedRoute struct {
	Family           string
	Prefix           string
	SRv6SID          string
	EndpointBehavior uint32
	NextHop          string
	VRF              string
}

// LocalSID names an allocation. Address stability holds within one daemon run;
// it does not extend across daemon restarts.
type LocalSID struct {
	Name     string
	Locator  string
	Slot     uint32
	AuxRaw   []byte
	DecapVRF string
}

type LogLevel int32

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)
