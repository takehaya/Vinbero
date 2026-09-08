//go:build bench

package benchrq1

// Convergence instrument for RQ1.
//
// The measurement it has to support is: a route changes, and we want the
// timestamp of the first packet that the data plane forwarded along the new
// path. Calibration uses a 151 us timing budget, so samples have to be dense
// enough that a window of that size contains several of them.
//
// Two decisions follow from that and are worth stating, because they are what
// separate this from the liveness prober in pkg/prober:
//
//   - Every packet carries its own send timestamp and a sequence number, and
//     the receiver stamps arrivals from the kernel via SO_TIMESTAMPNS. Nothing
//     is inferred from the schedule, so pacing jitter costs sample density but
//     never corrupts a timestamp.
//   - There is no hysteresis. The prober deliberately waits for consecutive
//     losses before it believes a path is down; convergence wants the opposite,
//     the very first arrival, so the two cannot share code.
//
// Receivers are per endpoint. Which receiver a sequence number lands on is what
// identifies the path taken, which is also how misdelivery is counted: a packet
// that arrives at the endpoint the route no longer points to.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The wire payload carries a sequence, truncated send timestamp and traffic
// tag. Endpoint identity comes from the receiver's capture.
const (
	probePayloadSize = 20
	probeMagic       = uint32(0x5652_5131) // "VRQ1"
)

type probeWire struct {
	Magic  uint32
	Tag    uint32
	Seq    uint64
	SendNs int64
}

func encodeProbe(buf []byte, p probeWire) {
	binary.BigEndian.PutUint32(buf[0:4], p.Magic)
	binary.BigEndian.PutUint32(buf[4:8], p.Tag)
	binary.BigEndian.PutUint64(buf[8:16], p.Seq)
	binary.BigEndian.PutUint32(buf[16:20], uint32(p.SendNs))
}

// decodeProbe returns the sequence and tag. The send timestamp is carried in
// full by the sender's own record; the truncated copy on the wire only exists
// so a capture without the sender's log is still interpretable.
func decodeProbe(buf []byte) (probeWire, bool) {
	if len(buf) < probePayloadSize {
		return probeWire{}, false
	}
	p := probeWire{
		Magic:  binary.BigEndian.Uint32(buf[0:4]),
		Tag:    binary.BigEndian.Uint32(buf[4:8]),
		Seq:    binary.BigEndian.Uint64(buf[8:16]),
		SendNs: int64(binary.BigEndian.Uint32(buf[16:20])),
	}
	if p.Magic != probeMagic {
		return probeWire{}, false
	}
	return p, true
}

// SendRecord is one emitted packet.
type SendRecord struct {
	Seq    uint64
	Tag    uint32
	SentAt time.Time
}

// RecvRecord is one observed arrival. Endpoint names the receiver that saw it;
// Analyze compares it with the configured old and new endpoint names.
type RecvRecord struct {
	Seq      uint64
	Tag      uint32
	Endpoint string
	RecvAt   time.Time
}

// SenderConfig configures one traffic source.
type SenderConfig struct {
	// Target is where probes go.
	Target netip.AddrPort
	// Tag is an opaque traffic identifier carried in the packet and captures.
	Tag uint32
	// Rate is the target packets per second. The achieved rate is reported
	// separately; it is never assumed.
	Rate int
	// Duration bounds the run.
	Duration time.Duration
}

// Sender emits probes and records what it actually sent.
type Sender struct {
	fd      int
	cfg     SenderConfig
	records []SendRecord
}

func NewSender(cfg SenderConfig) (*Sender, error) {
	if !cfg.Target.IsValid() {
		return nil, errors.New("probe: invalid target")
	}
	if cfg.Rate <= 0 {
		return nil, errors.New("probe: rate must be positive")
	}
	if int64(cfg.Rate) > int64(time.Second) {
		return nil, errors.New("probe: rate exceeds nanosecond pacing resolution")
	}

	domain := unix.AF_INET6
	if cfg.Target.Addr().Is4() {
		domain = unix.AF_INET
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("probe: socket: %w", err)
	}
	sa, err := sockaddrOf(cfg.Target)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// Connect so each send skips route lookup and address copying; at 100k
	// packets per second that overhead would otherwise cap the rate.
	if err := unix.Connect(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("probe: connect: %w", err)
	}

	capacity := cfg.Rate * int(cfg.Duration/time.Second+1)
	if capacity <= 0 || capacity > 1<<24 {
		capacity = 1 << 20
	}
	return &Sender{fd: fd, cfg: cfg, records: make([]SendRecord, 0, capacity)}, nil
}

func (s *Sender) Close() error { return unix.Close(s.fd) }

// Run emits probes until the configured duration elapses. Pacing is a spin
// against the clock: at a 10 us gap a sleep would overshoot by more than the
// gap itself, and burning one core is acceptable for an instrument.
func (s *Sender) Run() error {
	gap := time.Duration(int64(time.Second) / int64(s.cfg.Rate))
	buf := make([]byte, probePayloadSize)

	start := time.Now()
	deadline := start.Add(s.cfg.Duration)
	next := start

	for seq := uint64(0); ; seq++ {
		now := time.Now()
		if !now.Before(deadline) || !next.Before(deadline) {
			return nil
		}
		if wait := next.Sub(now); wait > 0 {
			if wait > 100*time.Microsecond {
				time.Sleep(wait - 50*time.Microsecond)
			}
			for time.Now().Before(next) {
			}
		}

		sentAt := time.Now()
		if !sentAt.Before(deadline) {
			return nil
		}
		encodeProbe(buf, probeWire{
			Magic:  probeMagic,
			Tag:    s.cfg.Tag,
			Seq:    seq,
			SendNs: sentAt.UnixNano(),
		})
		if _, err := unix.Write(s.fd, buf); err != nil {
			if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
				// A full transmit queue is a lost sample, not a failed
				// run; record nothing and keep the schedule.
				next = next.Add(gap)
				continue
			}
			return fmt.Errorf("probe: write seq %d: %w", seq, err)
		}
		s.records = append(s.records, SendRecord{Seq: seq, Tag: s.cfg.Tag, SentAt: sentAt})
		next = next.Add(gap)
	}
}

// Records returns what was sent, in order.
func (s *Sender) Records() []SendRecord { return s.records }

// Receiver observes arrivals at one endpoint with kernel receive timestamps.
type Receiver struct {
	fd       int
	name     string
	mu       sync.Mutex
	records  []RecvRecord
	stopOnce sync.Once
	done     chan struct{}
	runMu    sync.Mutex
	started  bool
	runDone  chan struct{}
}

// NewReceiver binds an endpoint. name identifies it in the records for
// comparison with Analyze's old and new endpoint names.
func NewReceiver(name string, bind netip.AddrPort) (*Receiver, error) {
	if !bind.IsValid() {
		return nil, errors.New("probe: invalid bind address")
	}
	domain := unix.AF_INET6
	if bind.Addr().Is4() {
		domain = unix.AF_INET
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("probe: socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("probe: reuseaddr: %w", err)
	}
	// Kernel receive timestamps. Stamping in user space would fold the
	// scheduler delay of this process into every arrival, which at a 10 us
	// sample gap is the difference between a usable and a useless number.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("probe: timestampns: %w", err)
	}
	// A short poll timeout keeps Stop responsive without a self-pipe.
	tv := unix.Timeval{Sec: 0, Usec: 200_000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("probe: rcvtimeo: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("probe: rcvbuf: %w", err)
	}
	sa, err := sockaddrOf(bind)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("probe: bind: %w", err)
	}
	return &Receiver{fd: fd, name: name, done: make(chan struct{}), runDone: make(chan struct{})}, nil
}

// Run reads until Stop. It is meant to run in its own goroutine.
func (r *Receiver) Run() error {
	r.runMu.Lock()
	select {
	case <-r.done:
		r.runMu.Unlock()
		return nil
	default:
	}
	if r.started {
		r.runMu.Unlock()
		return errors.New("probe: receiver Run may only be called once")
	}
	r.started = true
	r.runMu.Unlock()
	defer close(r.runDone)

	buf := make([]byte, 2048)
	oob := make([]byte, 256)

	for {
		select {
		case <-r.done:
			return nil
		default:
		}

		n, oobn, _, _, err := unix.Recvmsg(r.fd, buf, oob, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) ||
				errors.Is(err, unix.EINTR) {
				continue
			}
			select {
			case <-r.done:
				return nil
			default:
			}
			return fmt.Errorf("probe: recvmsg: %w", err)
		}
		p, ok := decodeProbe(buf[:n])
		if !ok {
			continue
		}
		recvAt, ok := timestampFromOOB(oob[:oobn])
		if !ok {
			return errors.New("probe: received packet without a kernel timestamp")
		}
		r.mu.Lock()
		r.records = append(r.records, RecvRecord{
			Seq:      p.Seq,
			Tag:      p.Tag,
			Endpoint: r.name,
			RecvAt:   recvAt,
		})
		r.mu.Unlock()
	}
}

// Stop ends Run and releases the socket.
func (r *Receiver) Stop() {
	r.stopOnce.Do(func() {
		close(r.done)
		r.runMu.Lock()
		started := r.started
		r.runMu.Unlock()
		if started {
			// Keep the descriptor open even if Run is descheduled longer
			// than its socket timeout. It must finish before fd reuse.
			<-r.runDone
		}
		r.runMu.Lock()
		_ = unix.Close(r.fd)
		r.runMu.Unlock()
	})
}

// LocalPort reports the port actually bound, so a caller may bind port 0 and
// let the kernel choose.
func (r *Receiver) LocalPort() (uint16, error) {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	select {
	case <-r.done:
		return 0, errors.New("probe: receiver is stopped")
	default:
	}
	sa, err := unix.Getsockname(r.fd)
	if err != nil {
		return 0, fmt.Errorf("probe: getsockname: %w", err)
	}
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		return uint16(v.Port), nil
	case *unix.SockaddrInet6:
		return uint16(v.Port), nil
	default:
		return 0, errors.New("probe: unexpected socket address family")
	}
}

// Records returns observed arrivals.
func (r *Receiver) Records() []RecvRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecvRecord, len(r.records))
	copy(out, r.records)
	return out
}

func timestampFromOOB(oob []byte) (time.Time, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}, false
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SO_TIMESTAMPNS {
			continue
		}
		var sec, nsec int64
		switch len(m.Data) {
		case 8: // native timespec on 32-bit Linux
			sec = int64(int32(binary.NativeEndian.Uint32(m.Data[:4])))
			nsec = int64(int32(binary.NativeEndian.Uint32(m.Data[4:8])))
		case 16: // native timespec on 64-bit Linux
			sec = int64(binary.NativeEndian.Uint64(m.Data[:8]))
			nsec = int64(binary.NativeEndian.Uint64(m.Data[8:16]))
		default:
			continue
		}
		if nsec < 0 || nsec >= int64(time.Second) {
			return time.Time{}, false
		}
		return time.Unix(sec, nsec), true
	}
	return time.Time{}, false
}

func sockaddrOf(ap netip.AddrPort) (unix.Sockaddr, error) {
	addr := ap.Addr()
	if addr.Is4() {
		sa := &unix.SockaddrInet4{Port: int(ap.Port())}
		sa.Addr = addr.As4()
		return sa, nil
	}
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
		sa := &unix.SockaddrInet4{Port: int(ap.Port())}
		sa.Addr = addr.As4()
		return sa, nil
	}
	sa := &unix.SockaddrInet6{Port: int(ap.Port())}
	sa.Addr = addr.As16()
	return sa, nil
}

// Convergence is the verdict of one route change.
type Convergence struct {
	// Detected is true when a packet reached the new endpoint.
	Detected bool
	// Latency is from the route change to the first arrival at the new
	// endpoint.
	Latency time.Duration
	// FirstSeq is the sequence number of that first arrival.
	FirstSeq uint64
	// Lost counts probes sent after the change that reached no endpoint.
	Lost int
	// Misdelivered counts post-change probes delivered to the old endpoint
	// before the first observed arrival at the new endpoint.
	Misdelivered int
	// SampleGap is the median spacing of arrivals, the resolution floor of
	// this run. A latency of the same order as SampleGap is not resolved.
	SampleGap time.Duration
}

// Analyze correlates one sender's log with every receiver's arrivals around a
// route change. newEndpoint is the receiver the route points to after the
// change; oldEndpoint is where it pointed before.
func Analyze(sent []SendRecord, received []RecvRecord, changeAt time.Time, oldEndpoint, newEndpoint string) Convergence {
	postChange := make(map[uint64]struct{}, len(sent))
	for _, s := range sent {
		if !s.SentAt.Before(changeAt) {
			postChange[s.Seq] = struct{}{}
		}
	}
	arrivals := make(map[uint64]RecvRecord, len(postChange))
	oldArrivals := make(map[uint64]time.Time)
	var out Convergence
	var firstNew time.Time
	for _, r := range received {
		if _, ok := postChange[r.Seq]; !ok || r.RecvAt.Before(changeAt) {
			continue
		}
		if r.Endpoint != oldEndpoint && r.Endpoint != newEndpoint {
			continue
		}
		if prev, ok := arrivals[r.Seq]; !ok || r.RecvAt.Before(prev.RecvAt) {
			arrivals[r.Seq] = r
		}
		// Sequence order can differ from arrival order. A duplicate reaching
		// both endpoints must also not hide the first observation on the new
		// path merely because the old endpoint received its copy earlier.
		if r.Endpoint == newEndpoint && (!out.Detected || r.RecvAt.Before(firstNew)) {
			out.Detected = true
			out.Latency = r.RecvAt.Sub(changeAt)
			out.FirstSeq = r.Seq
			firstNew = r.RecvAt
		}
		if r.Endpoint == oldEndpoint {
			if prev, ok := oldArrivals[r.Seq]; !ok || r.RecvAt.Before(prev) {
				oldArrivals[r.Seq] = r.RecvAt
			}
		}
	}
	out.Lost = len(postChange) - len(arrivals)
	for _, at := range oldArrivals {
		if !out.Detected || at.Before(firstNew) {
			out.Misdelivered++
		}
	}
	arrivalTimes := make([]int64, 0, len(arrivals))
	for _, r := range arrivals {
		arrivalTimes = append(arrivalTimes, r.RecvAt.UnixNano())
	}
	slices.Sort(arrivalTimes)
	gaps := make([]time.Duration, 0, len(arrivalTimes))
	for i := 1; i < len(arrivalTimes); i++ {
		gaps = append(gaps, time.Duration(arrivalTimes[i]-arrivalTimes[i-1]))
	}
	out.SampleGap = medianDuration(gaps)
	return out
}

func medianDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(d))
	copy(cp, d)
	slices.Sort(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return cp[mid-1] + (cp[mid]-cp[mid-1])/2
	}
	return cp[mid]
}
