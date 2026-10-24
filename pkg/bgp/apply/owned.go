package apply

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/takehaya/vinbero/pkg/headend"
	"net"
	"net/netip"
	"strings"

	"github.com/takehaya/vinbero/pkg/bpf"
	"go.uber.org/zap"
)

// Owner inventories include cleanup remnants whose forward entry is gone.
// Drain FDB references before freeing peers; replay recreates the current RIB.
func (a *Applier) sweepOwnedEVPNEntries() bool {
	owner := bpf.OwnerBGPEVPN(a.localASN)
	fdbs, err := a.fdbBd.ListFdbOwners()
	if err != nil {
		a.logger.Error("list EVPN FDB owners", zap.Error(err))
		return false
	}
	complete := true
	for key, tag := range fdbs {
		if tag != owner {
			continue
		}
		if err := a.fdbBd.DeleteFdbOwned(key.BdId, net.HardwareAddr(key.Mac[:]), owner); err != nil {
			a.logger.Error("sweep owned EVPN FDB", zap.Error(err))
			complete = false
		}
	}
	if !complete {
		return false
	}
	peers, err := a.fdbBd.ListBdPeerOwners()
	if err != nil {
		a.logger.Error("list EVPN peer owners", zap.Error(err))
		return false
	}
	for key, tag := range peers {
		if tag != owner {
			continue
		}
		if _, err := a.fdbBd.DeleteBdPeerOwned(key.BdId, key.Index, owner); err != nil {
			a.logger.Error("sweep owned EVPN peer", zap.Error(err))
			complete = false
		}
	}
	return complete
}

// Startup remnants are distinct from replayed session state. A replay must not
// overwrite a pending key and then have the old cleanup delete its replacement.
type mupRecoveryKey struct {
	instance uint32
	endpoint netip.Addr
	teid     uint32
	bits     uint8
	owner    bpf.OwnerTag
}
type mupStartupRecovery struct {
	pending map[mupRecoveryKey]bool
	gates   map[netip.Addr]bool
	rescan  bool
}
type mupOwnerInventory interface {
	ListMupUplinkV4Owners() (map[bpf.MupUplinkV4Key]bpf.OwnerTag, error)
	ListMupUplinkV6Owners() (map[bpf.MupUplinkV6Key]bpf.OwnerTag, error)
}

// A live instance move can leave the same kind of owned remnant as startup.
// Protect it independently of the current session's gate reference.
func (a *Applier) rememberMUPOwnedCleanup(key mupRecoveryKey) {
	if a.mupRecovery == nil {
		a.mupRecovery = &mupStartupRecovery{pending: map[mupRecoveryKey]bool{}, gates: map[netip.Addr]bool{}}
	}
	a.mupRecovery.pending[key] = true
	a.retryMUPOwnedCleanup()
}

// Reset built-in MUP entries before replay, leaving every foreign owner alone.
func (a *Applier) resetMUPOwned() {
	if _, ok := a.mupUplink.(mupOwnerInventory); !ok {
		return
	}
	a.mupRecovery = &mupStartupRecovery{pending: map[mupRecoveryKey]bool{}, gates: map[netip.Addr]bool{}, rescan: true}
	a.retryMUPOwnedCleanup()
}

func (a *Applier) scanMUPOwned() bool {
	inventory := a.mupUplink.(mupOwnerInventory)
	v4, err4 := inventory.ListMupUplinkV4Owners()
	v6, err6 := inventory.ListMupUplinkV6Owners()
	if err4 != nil || err6 != nil {
		a.logger.Error("MUP owner inventory", zap.Error(errors.Join(err4, err6)))
		return false
	}
	prefix := string(bpf.OwnerBGPMUP(a.localASN, ""))
	for k, o := range v4 {
		if strings.HasPrefix(string(o), prefix) {
			a.mupRecovery.pending[mupRecoveryKey{binary.BigEndian.Uint32(k.Instance[:]), netip.AddrFrom4(k.Endpoint), binary.BigEndian.Uint32(k.Teid[:]), uint8(k.Prefixlen - 64), o}] = true
		}
	}
	for k, o := range v6 {
		if strings.HasPrefix(string(o), prefix) {
			a.mupRecovery.pending[mupRecoveryKey{binary.BigEndian.Uint32(k.Instance[:]), netip.AddrFrom16(k.Endpoint), binary.BigEndian.Uint32(k.Teid[:]), uint8(k.Prefixlen - 160), o}] = true
		}
	}
	a.mupRecovery.rescan = false
	return true
}

// RetryMUPOwnedCleanup can be called by host reconciliation even when all MUP
// routes are delegated and no built-in route callback will arrive.
func (a *Applier) RetryMUPOwnedCleanup() {
	a.mupMu.Lock()
	defer a.mupMu.Unlock()
	hasRecovery := a.mupRecovery != nil && (a.mupRecovery.rescan || len(a.mupRecovery.pending) > 0 || len(a.mupRecovery.gates) > 0)
	if hasRecovery {
		a.retryMUPOwnedCleanup()
	}
	for key, st := range a.mupT2ST {
		if hasRecovery || st.withdrawn || (st.gateHeld && st.installedSID == "") {
			a.reconcileMUPT2ST(key)
		}
	}
}

func (a *Applier) retryMUPOwnedCleanup() {
	recovery := a.mupRecovery
	if recovery == nil {
		return
	}
	if recovery.rescan && !a.scanMUPOwned() {
		return
	}
	keep := map[netip.Addr]bool{}
	for k := range recovery.pending {
		var err error
		if k.endpoint.Is4() {
			err = a.mupUplink.DeleteMupUplinkV4Owned(k.instance, k.endpoint.String(), k.teid, k.bits, k.owner)
		} else {
			err = a.mupUplink.DeleteMupUplinkV6Owned(k.instance, k.endpoint.String(), k.teid, k.bits, k.owner)
		}
		if err != nil {
			a.logger.Error("MUP startup cleanup; retaining gate", zap.Error(err))
			keep[k.endpoint] = true
		} else {
			delete(recovery.pending, k)
		}
	}
	owner := bpf.OwnerTag(string(bpf.OwnerBGPMUPGate(a.localASN)) + ":recovery")
	for ep := range keep {
		dp := a.mupT2STDataPlane(ep, ep.String())
		af := headend.AFv4
		if ep.Is6() {
			af = headend.AFv6
		}
		var err error
		if shared, ok := a.headend.(interface {
			KeepGateReferences(headend.Family, string, uint8, bpf.OwnerTag, int) error
		}); ok {
			// Record the dependency even if restoring the physical map entry fails.
			recovery.gates[ep] = true
			err = shared.KeepGateReferences(af, dp.gatePrefix, dp.gateMode, owner, 1)
		} else if !recovery.gates[ep] {
			err = a.acquireMUPGate(dp.gatePrefix, dp.gateMode, bpf.OwnerBGPMUPGate(a.localASN), dp.createGate)
			if err == nil {
				recovery.gates[ep] = true
			}
		}
		if err != nil {
			a.logger.Error("restore MUP recovery gate", zap.Error(err))
		}
	}
	for ep := range recovery.gates {
		if keep[ep] {
			continue
		}
		dp := a.mupT2STDataPlane(ep, ep.String())
		if shared, ok := a.headend.(sharedMUPGate); ok {
			af := headend.AFv4
			if ep.Is6() {
				af = headend.AFv6
			}
			if err := shared.SetGateReferences(af, dp.gatePrefix, dp.gateMode, owner, 0); err != nil {
				a.logger.Error("release MUP recovery gate", zap.Error(err))
				continue
			}
		} else if !a.releaseMUPGate(dp.gatePrefix, bpf.OwnerBGPMUPGate(a.localASN), dp.deleteGate) {
			continue
		}
		delete(recovery.gates, ep)
	}
}

func (a *Applier) createMUPUplinkOwned(instance uint32, endpoint string, teid uint32, bits uint8, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	ep, err := netip.ParseAddr(endpoint)
	if err != nil {
		return err
	}
	if r := a.mupRecovery; r != nil {
		// A failed inventory has unknown keys, so defer new uplink writes until it
		// can be read. Sessions and discovery routes are still retained for replay.
		if r.rescan {
			return fmt.Errorf("MUP startup inventory unavailable")
		}
		if r.pending[mupRecoveryKey{instance, ep, teid, bits, owner}] {
			return fmt.Errorf("MUP startup cleanup pending for key")
		}
	}
	if ep.Is4() {
		return a.mupUplink.CreateMupUplinkV4Owned(instance, endpoint, teid, bits, entry, owner)
	}
	return a.mupUplink.CreateMupUplinkV6Owned(instance, endpoint, teid, bits, entry, owner)
}
