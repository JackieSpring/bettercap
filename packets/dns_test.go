package packets

import (
	"testing"

	"github.com/bettercap/bettercap/network"
	"github.com/google/gopacket/layers"
)

func TestMain(t *testing.T) {

	query := layers.DNSQuestion{
		Name:  []byte("dom"),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassAny,
	}

	ed1 := network.NewEndpoint("::1", "10:10:10:10:10:10")
	ed2 := network.NewEndpoint("::2", "11:11:11:11:11:11")

	conf := DNSConf{
		Questions: []layers.DNSQuestion{query},
	}

	dns, err := NewDNS(ed1, ed2, conf)

	if err != nil {
		t.Error(err)
		return
	}

	println(dns.Dump())

}
