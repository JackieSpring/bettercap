package packets

import (
	"fmt"
	"net"

	"github.com/bettercap/bettercap/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const UDP_PORT_DEFAULT = 12345

type LayerConfUDP struct {
	LayerConf
	srcPort uint16
	dstPort uint16
}

func NewUDPProbe(from net.IP, from_hw net.HardwareAddr, to net.IP, port int) (error, []byte) {
	eth := layers.Ethernet{
		SrcMAC:       from_hw,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(UDP_PORT_DEFAULT),
		DstPort: layers.UDPPort(port),
	}
	udp.Payload = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}

	if to.To4() == nil {
		ip6 := layers.IPv6{
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
			SrcIP:      from,
			DstIP:      to,
			HopLimit:   64,
		}

		udp.SetNetworkLayerForChecksum(&ip6)

		return Serialize(&eth, &ip6, &udp)
	} else {
		ip4 := layers.IPv4{
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      64,
			SrcIP:    from,
			DstIP:    to,
		}

		udp.SetNetworkLayerForChecksum(&ip4)

		return Serialize(&eth, &ip4, &udp)
	}
}

func NewUDP(src *network.Endpoint, dst *network.Endpoint, dstPort uint16) (ret gopacket.Packet, err error) {

	if ret, err = NewEthernet(src, dst, layers.EthernetTypeIPv4); err != nil {
		return nil, err
	}
	ret_bld := ret.(gopacket.PacketBuilder)

	var ip gopacket.Layer
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6

	if src.IP.To4() != nil && dst.IP.To4() != nil {
		ipv4, err = NewIPv4Layer(src, dst, layers.IPProtocolUDP)
		ip = &ipv4
	} else if src.IP.To16() != nil && dst.IP.To16() != nil {
		ipv6, err = NewIPv6Layer(src, dst, layers.IPProtocolUDP)
		ip = &ipv6
	} else {
		return nil, fmt.Errorf("illegal argument: NewUDP: IP address type missmatch")
	}

	if err != nil {
		return nil, err
	}

	udp, err := NewUDPLayer(UDP_PORT_DEFAULT, dstPort)
	if err != nil {
		return nil, err
	}

	udp.(*layers.UDP).SetNetworkLayerForChecksum(ip.(*layers.IPv4))

	ret_bld.AddLayer(ip)
	ret_bld.AddLayer(udp)

	return ret, nil
}

func NewUDPLayer(c LayerConf) (ret gopacket.Layer, err error) {
	conf := c.(LayerConfUDP)

	udp := ret.(*layers.UDP)
	udp.DstPort = layers.UDPPort(conf.dstPort)
	udp.SrcPort = layers.UDPPort(conf.srcPort)

	return udp, nil
}
