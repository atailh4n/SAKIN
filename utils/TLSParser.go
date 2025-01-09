/**
* TLSParser.go - Parsing CLientHello and TLS connections
* Written by: atailh4n
 */

package Utils

import (
	"log"
)

// ParseTLSClientHello parses a TLS ClientHello message and extracts the SNI if available.
func ParseTLSClientHello(payload []byte) (bool, string) {
	// Check if the payload contains a TLS handshake record (at least 5 bytes for record header)
	if len(payload) < 5 {
		log.Println("Payload is too short to be a valid TLS ClientHello")
		return false, ""
	}

	// Check if the record type is Handshake (0x16)
	if payload[0] != 0x16 { // 0x16 is the TLS record type for Handshake
		log.Println("Not a TLS Handshake message")
		return false, ""
	}

	// Check if it is a ClientHello (HandshakeType == 0x01)
	if len(payload) < 43 || payload[5] != 0x01 { // 0x01 is the ClientHello type
		log.Println("Not a TLS ClientHello message")
		return false, ""
	}

	// Extract the length of the message and check if there is enough data
	offset := 6
	helloLength := uint16(payload[offset])<<8 | uint16(payload[offset+1])
	offset += 2 // move past the length field

	// Ensure the total length of the payload is at least as long as the ClientHello message
	if len(payload) < offset+int(helloLength) {
		log.Printf("Payload length is too short, expected length: %d, actual length: %d", offset+int(helloLength), len(payload))
		return false, ""
	}

	// Skip protocol version (2 bytes)
	offset += 2

	// Skip random (32 bytes) and session ID length (1 byte) + session ID (variable)
	offset += 33

	// Skip cipher suites length (2 bytes) + cipher suites (variable length)
	offset += 2 + int(payload[offset-1])

	// Skip compression methods length (1 byte) + compression methods (variable length)
	if (offset - 1) > len(payload) {
		log.Println("SAKIN PANICover: Index out of the range")
		return false, ""
	}
	offset += 1 + int(payload[offset-1])

	// Check if there are extensions, and if so, try to parse them
	if len(payload) > offset {
		// Now we are at the extensions area
		for offset+4 <= len(payload) {
			extType := uint16(payload[offset])<<8 | uint16(payload[offset+1])
			extLength := int(payload[offset+2])<<8 | int(payload[offset+3])
			offset += 4

			// Ensure the extension length does not exceed available bytes
			if offset+extLength > len(payload) {
				log.Println("Extension length exceeds available data")
				return false, ""
			}

			// Check if extension type is Server Name Indication (0x00)
			if extType == 0x00 {
				if offset+extLength <= len(payload) {
					sni := string(payload[offset : offset+extLength])
					log.Printf("Detected SNI: %s", sni)
					return true, sni
				} else {
					log.Println("Invalid SNI extension length")
					return false, ""
				}
			}

			// Move to next extension
			offset += extLength
		}
	}

	log.Println("No SNI extension found")
	return false, ""
}
