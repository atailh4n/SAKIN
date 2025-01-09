/**
* SAKINCore.go - Core Process
* Written by: atailh4n
 */

package main

import (
	"log"
	"sync"

	Handlers "github.com/atailh4n/sakin/handlers"
	Utils "github.com/atailh4n/sakin/utils"
	"github.com/google/gopacket/pcap"
)

func main() {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	db, err := Handlers.InitDB()
	if err != nil {
		log.Fatalf("PostgreSQL connection error: %v", err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	Utils.MonitorTraffic(ifaces, db, &wg)
	wg.Wait()
}
