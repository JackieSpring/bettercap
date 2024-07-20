package packets

import (
	"fmt"

	net "github.com/bettercap/bettercap/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewEthernet(src *net.Endpoint, dst *net.Endpoint, next layers.EthernetType) (gopacket.Packet, error) {

	eth, err := NewEthernetLayer(src, dst, 0)
	if err != nil {
		return nil, err
	}

	ret := gopacket.NewPacket(eth.Contents, layers.LayerTypeEthernet, gopacket.Default)

	return ret, nil
}

func NewEthernetLayer(src *net.Endpoint, dst *net.Endpoint, next layers.EthernetType) (ret layers.Ethernet, err error) {

	if src == nil || dst == nil {
		return ret, fmt.Errorf("illegal argument: NewEthernetLayer: missing src or dst")
	}

	ret.SrcMAC = src.HW
	ret.DstMAC = dst.HW
	ret.EthernetType = next

	return ret, nil
}
