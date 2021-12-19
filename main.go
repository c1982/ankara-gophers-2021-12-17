package main

import (
	"bytes"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
  
  //TODO: change device name 
	handler, err := pcap.OpenLive("en0", 2048, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	defer handler.Close()

  //only listens on port 80 
	_ = handler.SetBPFFilter("ip and tcp port 80")

	getSignature := []byte("GET")
	log4shellSignature := []byte("${jndi:ldap")

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		ethlayer := packet.Layer(layers.LayerTypeEthernet)
		eth, ok := ethlayer.(*layers.Ethernet)
		if !ok {
			continue
		}

		iplayer := packet.Layer(layers.LayerTypeIPv4)
		ip, ok := iplayer.(*layers.IPv4)
		if !ok {
			continue
		}

		tcplayer := packet.Layer(layers.LayerTypeTCP)
		tcp, ok := tcplayer.(*layers.TCP)
		if !ok {
			continue
		}

		payload := tcp.LayerPayload()
		fmt.Printf("src:%s:%d (%s), dst: %s:%d (%s)\r\n", ip.SrcIP, tcp.SrcPort, eth.SrcMAC, ip.DstIP, tcp.DstPort, eth.DstMAC)

		if bytes.HasPrefix(payload, getSignature) {
			fmt.Println("GET request detected!")
		}

		if bytes.Contains(payload, log4shellSignature) {
			fmt.Println("Ohhh! noo! log4shell attack detected!1")

			resp, err := blockLog4shell(*eth, *ip, *tcp)
			if err != nil {
				fmt.Println(err)
				continue
			}

			err = handler.WritePacketData(resp)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

}

func blockLog4shell(eth layers.Ethernet, ip layers.IPv4, tcp layers.TCP) (resp []byte, err error) {
	neweth := layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: eth.EthernetType,
	}

	newip := layers.IPv4{
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
		Version:  ip.Version,
		Id:       ip.Id,
		Protocol: ip.Protocol,
		TTL:      77,
	}

	newtcp := layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		ACK:     true,
		PSH:     true,
		FIN:     true,
		Seq:     tcp.Ack,
		Ack:     tcp.Seq,
		Window:  0,
	}

	_ = newtcp.SetNetworkLayerForChecksum(&newip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	paylod := gopacket.Payload([]byte("<h1>Yassak!!</h1>"))
	err = gopacket.SerializeLayers(buf, opts, &neweth, &newip, &newtcp, paylod)
	if err != nil {
		return resp, err
	}

	return buf.Bytes(), nil
}
