/**
* Main.go written by atailh4n
 */

package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Sanitize function to make interface names valid for file names
func sanitizeName(name string) string {
	// Replace invalid characters with underscores
	re := regexp.MustCompile(`[<>:"/\\|?*]`)
	return re.ReplaceAllString(name, "_")
}

func main() {
	// List all available devices
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Iterate over all interfaces
	for _, iface := range ifaces {
		wg.Add(1) // Increment the wait group counter
		go func(ifaceName string) {
			defer wg.Done() // Decrement the counter when the goroutine completes

			handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
			if err != nil {
				log.Printf("Error opening interface %s: %v", ifaceName, err)
				return
			}
			defer handle.Close()

			// Sanitize the interface name for use in the log file
			sanitizedName := sanitizeName(ifaceName)

			// Get directory.
			dir, err := os.Getwd()
			if err != nil {
				log.Fatal(err)
			}

			// Create a log file for this interface
			logFile, err := os.OpenFile(fmt.Sprintf("%s/network_packets_%s.log", dir, sanitizedName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				log.Printf("Error opening log file for interface %s: %v", ifaceName, err)
				return
			}
			defer logFile.Close()

			// Create a new logger for logging packets
			logger := log.New(logFile, "", log.LstdFlags)

			// Use gopacket to capture packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					logger.Printf("Sender: %s, Receiver: %s, Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
				}
			}
		}(iface.Name) // Pass the interface name to the goroutine
	}

	wg.Wait() // Wait for all goroutines to finish
}
