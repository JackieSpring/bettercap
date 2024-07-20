package packets

import (
	"fmt"

	net "github.com/bettercap/bettercap/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	IPv6_TTL_DEFAULT = 64
	IPv6_VERSION     = 6
)

func NewIPv6(src *net.Endpoint, dst *net.Endpoint, next layers.IPProtocol) (gopacket.Packet, error) {

	eth, err := NewEthernetLayer(src, dst, layers.EthernetTypeIPv4)
	if err != nil {
		return nil, err
	}

	ip, err := NewIPv6Layer(src, dst, next)
	if err != nil {
		return nil, err
	}

	err, raw := Serialize(&eth, &ip)
	if err != nil {
		return nil, err
	}

	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default), nil

}

func NewIPv6Layer(src *net.Endpoint, dst *net.Endpoint, next layers.IPProtocol) (ret layers.IPv6, err error) {
	if src == nil || dst == nil {
		return ret, fmt.Errorf("illegal argument: NewIPv4Layer: missing src or dst")
	}

	if src.IP.To16() == nil || dst.IP.To16() == nil {
		return ret, fmt.Errorf("illegal argument: NewIPv6Layer: address is not IPv6")
	}

	ret = layers.IPv6{
		NextHeader: next,
		Version:    IPv6_VERSION,
		HopLimit:   IPv6_TTL_DEFAULT,
		SrcIP:      src.IP,
		DstIP:      dst.IP,
	}

	return ret, nil

}
