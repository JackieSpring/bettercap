package packets

import (
	"fmt"

	net "github.com/bettercap/bettercap/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	IPv4_TTL_DEFAULT = 64
	IPv4_VERSION     = 4
)

func NewIPv4(src *net.Endpoint, dst *net.Endpoint, next layers.IPProtocol) (gopacket.Packet, error) {

	eth, err := NewEthernetLayer(src, dst, layers.EthernetTypeIPv4)
	if err != nil {
		return nil, err
	}

	ip, err := NewIPv4Layer(src, dst, next)
	if err != nil {
		return nil, err
	}

	err, raw := Serialize(&eth, &ip)
	if err != nil {
		return nil, err
	}

	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default), nil

}

func NewIPv4Layer(src *net.Endpoint, dst *net.Endpoint, next layers.IPProtocol) (ret layers.IPv4, err error) {
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
