package nettrace

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PacketCapture is a recording of all/some packets that arrived or left through
// a given interface.
// This is typically included alongside NetTrace and captured packets are filtered
// to contain only those that correspond with the traced connections.
type PacketCapture struct {
	// InterfaceName : name of the interface on which the packets were captured
	// (on either direction).
	InterfaceName string
	// Packets : captured packets.
	Packets []gopacket.Packet
	// Truncated is returned as true if the capture does not contain all packets
	// because the maximum allowed total size would be exceeded otherwise.
	Truncated bool
}

// WriteToFile saves packet capture to a given file.
func (pc PacketCapture) WriteToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		return err
	}
	for _, packet := range pc.Packets {
		err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			return err
		}
	}
	return nil
}
