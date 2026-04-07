package packet

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GTPULayer implements GTP-U v1 (3GPP TS 29.281) with PDU Session Container support.
// gopacket's built-in GTPv1U doesn't correctly serialize extension headers,
// so this custom layer provides full control over the wire format.
type GTPULayer struct {
	layers.BaseLayer
	TEID uint32
	QFI  uint8 // 0 = no PDU Session Container
	RQI  uint8
}

var GTPULayerType = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		Name:    "GTPULayerType",
		Decoder: gopacket.DecodeFunc(decodeGTPULayer),
	},
)

func (g *GTPULayer) LayerType() gopacket.LayerType {
	return GTPULayerType
}

func (g *GTPULayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	hasPSC := g.QFI > 0

	var hdrLen int
	if hasPSC {
		hdrLen = 16 // mandatory(8) + optional(4) + PSC(4)
	} else {
		hdrLen = 8 // mandatory only
	}

	bytes, err := b.PrependBytes(hdrLen)
	if err != nil {
		return err
	}

	payloadLen := len(b.Bytes()) - hdrLen

	// Flags: Version=1, PT=1, E flag if PSC present
	if hasPSC {
		bytes[0] = 0x34 // V1 | PT | E
	} else {
		bytes[0] = 0x30 // V1 | PT
	}
	bytes[1] = 0xFF // G-PDU

	// Message length (everything after mandatory 8 bytes)
	if hasPSC {
		binary.BigEndian.PutUint16(bytes[2:4], uint16(4+4+payloadLen)) // opt + PSC + payload
	} else {
		binary.BigEndian.PutUint16(bytes[2:4], uint16(payloadLen))
	}

	// TEID
	binary.BigEndian.PutUint32(bytes[4:8], g.TEID)

	if hasPSC {
		// Optional header: seq=0, npdu=0, next_ext=0x85 (PDU Session Container)
		bytes[8] = 0x00
		bytes[9] = 0x00
		bytes[10] = 0x00
		bytes[11] = 0x85

		// PDU Session Container: length=1, type=DL(0), QFI, next=0
		bytes[12] = 0x01
		bytes[13] = 0x00
		bytes[14] = (g.QFI & 0x3F) | ((g.RQI & 0x01) << 6)
		bytes[15] = 0x00
	}

	return nil
}

func (g *GTPULayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return fmt.Errorf("GTP-U layer less than 8 bytes")
	}

	g.TEID = binary.BigEndian.Uint32(data[4:8])

	hdrLen := 8
	flags := data[0]
	hasOpt := flags&0x07 != 0 // E, S, or PN flag set

	if hasOpt {
		if len(data) < 12 {
			df.SetTruncated()
			return fmt.Errorf("GTP-U optional header truncated")
		}
		hdrLen = 12
		nextExt := data[11]

		// Walk extension headers to find PDU Session Container
		if nextExt == 0x85 && len(data) >= hdrLen+4 {
			g.QFI = data[hdrLen+2] & 0x3F
			g.RQI = (data[hdrLen+2] >> 6) & 0x01
			extLen := int(data[hdrLen]) * 4
			hdrLen += extLen
		}
	}

	g.BaseLayer = layers.BaseLayer{
		Contents: data[:hdrLen],
		Payload:  data[hdrLen:],
	}
	return nil
}

func (g *GTPULayer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeGTPULayer(data []byte, p gopacket.PacketBuilder) error {
	g := &GTPULayer{}
	if err := g.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(g)
	next := g.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
