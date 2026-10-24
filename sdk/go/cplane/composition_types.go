package cplane

// Composition replaces this plugin's whole forwarding and advertisement set.
// The host installs forwarding before advertisements and withdraws before prune.
type Composition struct {
	Revision       uint64
	Headends       []ForwardingHeadend
	Uplinks        []MUPUplink
	EVPN           []EVPNForward
	Advertisements []RawAdvertisement
}
type ForwardingHeadend struct {
	Context string
	Entry   HeadendEntry
}
type MUPUplink struct {
	Context, Endpoint string
	TEID              uint32
	TEIDBits          uint8
	Segments          []string
	SrcAddr           string
}

// EVPNForward supports a remote static MAC and/or a flood peer in one BD.
// Peer indices and bridge-domain identifiers are host derived from Context.
type EVPNForward struct {
	Context, MAC       string
	Segments           []string
	SrcAddr, RemoteSrc string
	Flood              bool
}

// RawAdvertisement uses the pinned GoBGP codec. The host derives RD/RT and
// checks SID ownership; initial advertisement profiles are VPN and IPv6 unicast.
type RawAdvertisement struct {
	Context, VRF string
	Path         *BGPPath
}
