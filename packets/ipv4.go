package packets

import (
	"fmt"

	"github.com/bettercap/bettercap/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerConfIP struct {
	LayerConf
	Src  *network.Endpoint
	Dst  *network.Endpoint
	Next layers.IPProtocol
}

func NewIPLayer(c LayerConf) (gopacket.Packet, error) {

	conf := c.(LayerConfIP)

	if conf.Src.IP.To4() != nil && conf.Dst.IP.To4() != nil {
		return NewIPv4Layer(c)
	}

}

func NewIPv4Layer(c LayerConf) (ret layers.IPv4, err error) {

	conf := c.(LayerConfIP)
	src := conf.Src
	dst := conf.Dst
	next := conf.Next

	if src == nil || dst == nil {
		return ret, fmt.Errorf("illegal argument: NewIPv4Layer: missing src or dst")
	}

	if src.IP.To4() == nil || dst.IP.To4() == nil {
		return ret, fmt.Errorf("illegal argument: NewIPv4Layer: address is not IPv4")
	}

	ret = layers.IPv4{
		Protocol: next,
		Version:  IPv4_VERSION,
		TTL:      IPv4_TTL_DEFAULT,
		SrcIP:    src.IP,
		DstIP:    dst.IP,
	}

	return ret, nil

}
