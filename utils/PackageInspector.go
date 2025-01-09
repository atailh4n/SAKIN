/**
* PackageInspector.go - DPI (Deep Package Inspection) and sanitizing tool
* Written by: atailh4n
 */

package Utils

import (
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"

	Handlers "github.com/atailh4n/sakin/handlers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// cleanString sanitizes the input string by removing non-printable characters.
func cleanString(s string) string {
	var cleaned string
	for _, r := range s {
		if r >= 32 && r <= 126 { // Only keep printable ASCII characters
			cleaned += string(r)
		}
	}
	return cleaned
}

// MonitorTraffic listens to network traffic on specified interfaces and processes packets.
func MonitorTraffic(ifaces []pcap.Interface, db *sql.DB, wg *sync.WaitGroup) {
	for _, iface := range ifaces {
		log.Printf("\nDetected network interface:\nDevice ID: %s, Device Description: %s\n", iface.Name, iface.Description)
		if strings.Contains(iface.Name, "Loopback") {
			log.Printf("\nSkipping loopback network interface:\nDevice ID: %s, Device Description: %s\n", iface.Name, iface.Description)
			return
		}
		wg.Add(1)

		// Start a goroutine for each interface
		go func(ifaceName string) {
			defer wg.Done()

			// Open the network interface for packet capture
			handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
			if err != nil {
				log.Printf("Error opening device %s: %v", ifaceName, err)
				return
			}
			log.Printf("Successfully opened network interface: %s\n", ifaceName)
			defer handle.Close()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			// Process each captured packet
			for packet := range packetSource.Packets() {
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					timestamp := time.Now()

					// Check if the packet contains a TLS ClientHello message
					if packet.ApplicationLayer() != nil {
						payload := packet.ApplicationLayer().Payload()
						if len(payload) > 0 {
							// Try parsing TLS ClientHello to check for SNI
							if isTLS, sni := ParseTLSClientHelloTemp(payload); isTLS {
								if sni != "" {
									log.Printf("Captured TLS ClientHello with SNI: %s\n", sni)
									cleanSni := cleanString(sni)

									// Save the SNI to the database
									err := Handlers.SaveSNI(db, cleanSni, ip.SrcIP.String(), ip.DstIP.String(), ip.Protocol.String(), timestamp)
									if err != nil {
										log.Printf("Error saving SNI to DB: %v", err)
									}
								} else {
									log.Printf("SNI is empty in ClientHello message.\n")
								}
							} else {
								log.Printf("Captured non-TLS or unsupported message.\n")
							}
						} else {
							log.Printf("Captured encrypted HTTPS traffic from %s to %s\n", ip.SrcIP, ip.DstIP)
						}
					}

					// Save the packet data to the database
					err := Handlers.SavePacket(db, ip.SrcIP.String(), ip.DstIP.String(), ip.Protocol.String(), timestamp)
					if err != nil {
						log.Printf("Error saving packet to DB: %v", err)
					}
				} else {
					log.Printf("Non-IP packet captured.\n")
				}
			}
		}(iface.Name)
	}
}
