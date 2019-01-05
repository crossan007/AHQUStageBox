package main

import (
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type DSPChannel struct {
	ChannelBytes []byte
}

var (
	pcapFile       string = "./Wiresharks/Allen-Heath.pcapng"
	file           *os.File
	err            error
	DSPBytes       []byte
	bytespersample int = 3
)

func main() {
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var llc layers.LLC
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &llc, &ip4, &ip6, &tcp, &udp, &payload)

	// Open file instead of device
	file, err = os.Open(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Loop through packets in file
	var DefaultNgReaderOptions = pcapgo.NgReaderOptions{}
	packetSource, err2 := pcapgo.NewNgReader(file, DefaultNgReaderOptions)
	if err2 != nil {
		log.Fatal("reader error: " + err.Error())
	}

	var packets = 100000
	log.Println("Decoding packets to DSPBytes")
	DSPBytes = make([]byte, bytespersample*packets)
	for i := 0; i < packets; i++ {
		data := getNextPacketBytes(packetSource)
		err = parser.DecodeLayers(data, &decodedLayers)
		if err != nil {
			//log.Println("  Error encountered:", err)
		}

		for _, typ := range decodedLayers {
			//log.Println("  Successfully decoded layer type", typ)
			if typ == layers.LayerTypeLLC {
				SplitPacket(eth.SrcMAC, llc.Payload, i)
			}
			/*switch typ {
			case layers.LayerTypeEthernet:
				log.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
			case layers.LayerTypeIPv4:
				log.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
			case layers.LayerTypeLLC:
				log.Println("    LLC ", hex.EncodeToString(llc.Payload))
			case layers.LayerTypeIPv6:
				log.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
			case layers.LayerTypeTCP:
				log.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
			case layers.LayerTypeUDP:
				log.Println("    UDP ", udp.SrcPort, udp.DstPort)
			}*/

		}

		//log.Println(hex.EncodeToString(data))
	}

	log.Println("Finished decoding packets to DSPBytes")

	FlushBuffers()

}
func FlushBuffers() {
	log.Println("Flushing buffers")
	f, err1 := os.OpenFile("00-04-c4-01-8b-46-2.wav", os.O_WRONLY|os.O_CREATE, 0644)
	if err1 != nil {
		log.Fatal(err1)
	}
	_, err2 := f.Write(DSPBytes)
	if err2 != nil {
		log.Fatal(err1)
	}
	f.Close()
	log.Println("Finished flushing buffers")
}
func SplitPacket(srcmac net.HardwareAddr, data []byte, index int) {

	var chanNum = 10
	var macaddr = strings.Replace(srcmac.String(), ":", "-", -1)
	//var filePrefix = "./" + macaddr + "/" + strings.Replace(srcmac.String(), ":", "-", -1)
	if macaddr != "00-04-c4-01-8b-46" {
		//if macaddr != "00-04-c4-01-a0-93" {
		return
	}
	//log.Println("Parsing frame: " + hex.EncodeToString(data))
	for i := chanNum; i < chanNum+1; i++ {
		//var filename = filePrefix + "-" + strconv.Itoa(i) + ".wav"
		var newbytes = data[(i * bytespersample) : (i*bytespersample)+bytespersample]

		//log.Println("copying to " + strconv.Itoa(index) + " DSPBytes " + hex.EncodeToString(newbytes))
		copy(DSPBytes[1+(index*bytespersample):], newbytes)
		/*
			f, err1 := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
			if err1 != nil {
				log.Fatal(err1)
			}
			_, err2 := f.Write()
			if err2 != nil {
				log.Fatal(err1)
			}
			f.Close()*/
	}

}

func getNextPacketBytes(packetSource *pcapgo.NgReader) []byte {
	data, ci, err := packetSource.ReadPacketData()
	if err != nil {
		log.Println(err)
	}
	_ = ci

	return data
}
