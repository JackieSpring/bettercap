package packets

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var factory *PacketFactory

type LayerConstructor func(LayerConf) (gopacket.Layer, error)
type PacketConstructor func(LayerConf) (gopacket.Packet, error)

type PacketFactory struct {
	formulas map[gopacket.LayerType]LayerConstructor
}

type LayerConf interface{}

// METHODS

func (lf *PacketFactory) SetFormula(lt gopacket.LayerType, lc LayerConstructor) {
	if lc == nil {
		return
	}
	lf.formulas[lt] = lc
}

func (lf *PacketFactory) GetFormula(lt gopacket.LayerType) (LayerConstructor, bool) {
	ret, fnd := lf.formulas[lt]
	return ret, fnd
}

func GetLayerFactory() *PacketFactory {
	return factory

}

// PACKAGE INIT

func init() {

	factory = &PacketFactory{
		formulas: make(map[gopacket.LayerType]LayerConstructor),
	}

	factory.SetFormula(layers.LayerTypeUDP, LayerConstructor(NewUDPLayer))
	//factory.formulas[layers.LayerTypeUDP] = NewUDPLayer

}
