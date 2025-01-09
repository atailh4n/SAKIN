/**
* DatabaseHandler.go - Handler for PostgreSQL
* Written by: atailh4n
 */

package Handlers

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // Go driver for PostgreSQL
)

// Initialize DB
func InitDB() (*sql.DB, error) {
	// PostgreSQL DSN (Data Source Name)
	dsn := "user=postgres password=test dbname=network_db host=127.0.0.1 port=5432 sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Verify connection to the database
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %v", err)
	}

	// Select the database
	_, err = db.Exec("SET search_path TO public")
	if err != nil {
		return nil, fmt.Errorf("database selection error: %v", err)
	}

	// // Create table
	// createTableQuery := `
	//   CREATE TABLE IF NOT EXISTS packets (
	// 	  id SERIAL PRIMARY KEY,   -- PostgreSQL'de AUTO_INCREMENT yerine SERIAL kullanılır
	// 	  src_ip VARCHAR(15),
	// 	  dst_ip VARCHAR(15),
	// 	  protocol VARCHAR(10),
	// 	  timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	//   )
	// `
	// _, err = db.Exec(createTableQuery)
	// if err != nil {
	// 	return nil, fmt.Errorf("table creation error : %v", err)
	// }

	return db, nil
}

// Save packets to DB
func SavePacket(db *sql.DB, srcIP, dstIP, protocol string, timestamp time.Time) error {
	query := "INSERT INTO \"PacketData\" (\"srcIp\", \"dstIp\", \"protocol\", \"timestamp\") VALUES ($1, $2, $3, $4)"
	_, err := db.Exec(query, srcIP, dstIP, protocol, timestamp)
	return err
}

// Save SNIs to DB
func SaveSNI(db *sql.DB, sni string, srcIP, dstIP, protocol string, timestamp time.Time) error {
	query := "INSERT INTO \"SniData\" (\"sni\", \"srcIp\", \"dstIp\", \"protocol\", \"timestamp\") VALUES ($1, $2, $3, $4, $5)"
	_, err := db.Exec(query, sni, srcIP, dstIP, protocol, timestamp)
	return err
}
