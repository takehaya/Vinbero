package cplane

import (
	"errors"
	"strconv"

	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
)

type Status int32

const (
	StatusOK Status = iota
	StatusInvalid
	StatusDenied
	StatusInternal
)

// Host is the declaration transport. guest.Host implements it in a WASM module;
// native tests can supply a recorder. Commit consumes its transaction on failure
// as well as success, matching the daemon ABI.
type Host interface {
	Begin(Kind) uint64
	Put(uint64, []byte) Status
	Commit(uint64) Status
	Abort(uint64)
}

var (
	ErrNoHost        = errors.New("cplane: no host configured")
	ErrBeginRefused  = errors.New("cplane: host refused to open declaration")
	ErrEntryTooLarge = errors.New("cplane: entry exceeds chunk size")
)

type ApplyError struct {
	Stage  string
	Status Status
}

func (e *ApplyError) Error() string {
	return "cplane: " + e.Stage + " failed with status " + strconv.Itoa(int(e.Status))
}

// Client submits complete desired sets. A nil or empty slice removes this
// plugin's entries of that kind. Live commits are synchronous and can partially
// apply before failing. During initialization the daemon stages commits until
// publication and owns retries of those staged declarations.
type Client struct {
	Host Host
	// MaxChunkBytes bounds each apply_put buffer, including protobuf framing.
	// Zero uses 32 KiB; set a smaller value for a host with a lower buffer limit.
	MaxChunkBytes int
}

func (c *Client) ApplyHeadendV4(entries []HeadendEntry) error {
	return c.apply(HeadendV4, len(entries), func(i int) []byte { return encodeHeadend(entries[i]) })
}
func (c *Client) ApplyHeadendV6(entries []HeadendEntry) error {
	return c.apply(HeadendV6, len(entries), func(i int) []byte { return encodeHeadend(entries[i]) })
}
func (c *Client) ApplyAdvertise(routes []AdvertisedRoute) error {
	return c.apply(Advertise, len(routes), func(i int) []byte { return encodeAdvertised(routes[i]) })
}
func (c *Client) ApplyLocalSIDs(sids []LocalSID) error {
	return c.apply(LocalSIDs, len(sids), func(i int) []byte { return encodeLocalSID(sids[i]) })
}

func (c *Client) apply(kind Kind, count int, encode func(int) []byte) error {
	if c.Host == nil {
		return ErrNoHost
	}
	limit := c.MaxChunkBytes
	if limit <= 0 {
		limit = 32 << 10
	}
	gen := c.Host.Begin(kind)
	if gen == 0 {
		return ErrBeginRefused
	}
	closed := false
	defer func() {
		if !closed {
			c.Host.Abort(gen)
		}
	}()
	var chunk []byte
	put := func() error {
		if status := c.Host.Put(gen, chunk); status != StatusOK {
			return &ApplyError{Stage: "put", Status: status}
		}
		chunk = chunk[:0]
		return nil
	}
	for i := 0; i < count; i++ {
		entry := encode(i)
		if len(entry) > limit {
			return ErrEntryTooLarge
		}
		if len(chunk) > 0 && len(chunk)+len(entry) > limit {
			if err := put(); err != nil {
				return err
			}
		}
		chunk = append(chunk, entry...)
	}
	if len(chunk) > 0 {
		if err := put(); err != nil {
			return err
		}
	}
	status := c.Host.Commit(gen)
	closed = true
	if status != StatusOK {
		return &ApplyError{Stage: "commit", Status: status}
	}
	return nil
}

func encodeHeadend(entry HeadendEntry) []byte {
	var body, chunk wire.Encoder
	body.String(1, entry.TriggerPrefix)
	for _, sid := range entry.Segments {
		body.Message(2, []byte(sid))
	}
	body.String(3, entry.SrcAddr)
	body.Uint(4, uint64(entry.Mode))
	chunk.Message(1, body)
	return chunk
}
func encodeAdvertised(route AdvertisedRoute) []byte {
	var body, chunk wire.Encoder
	body.String(1, route.Family)
	body.String(3, route.Prefix)
	body.String(4, route.SRv6SID)
	body.Uint(5, uint64(route.EndpointBehavior))
	body.String(7, route.NextHop)
	body.String(8, route.VRF)
	chunk.Message(2, body)
	return chunk
}
func encodeLocalSID(sid LocalSID) []byte {
	var body, chunk wire.Encoder
	body.String(1, sid.Name)
	body.String(2, sid.Locator)
	body.Uint(3, uint64(sid.Slot))
	body.Bytes(4, sid.AuxRaw)
	body.String(5, sid.DecapVRF)
	chunk.Message(3, body)
	return chunk
}
