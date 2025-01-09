# S.A.K.İ.N.

S.A.K.İ.N. is a cybersecurity project developed by Kaan Saydam and Ata İlhan Köktürk. Its primary purpose is to capture network traffic packets and analyze them for potential security vulnerabilities and exploits. The project focuses on deep packet inspection (DPI) to detect potential threats such as malicious payloads and unauthorized communication.

S.A.K.İ.N. stands for **"Siber Analiz Kontrol ve İstihbarat Noktası"**, which translates to **"Security Analysis and Knowledge Integration Node"**.

### Key Features:
- Monitors network traffic for potential security threats.
- Captures and analyzes TLS ClientHello messages to extract SNI (Server Name Indication).
- Logs SNI data for further analysis.
- Stores captured data in a PostgreSQL database.
- Visualizes network data through Prisma ORM with a clear schema for efficient handling and querying.

The tool is continuously evolving, and in future versions, it will support MongoDB for more scalable storage and enhanced visualization capabilities.

---

## Usage and Use Cases

Currently, S.A.K.İ.N. performs the following tasks:
1. **Traffic Monitoring:** Monitors network traffic on specified interfaces.
2. **TLS ClientHello Analysis:** Detects and logs SNI (Server Name Indication) from TLS ClientHello messages.
3. **Database Logging:** Saves information like source IP, destination IP, protocol, and timestamp into a PostgreSQL database.
4. **Data Visualization:** In future versions, MongoDB integration and data visualization will be introduced.

### Example Packages:
- Some example network packets have been provided for demonstration purposes. You can use them to understand how the tool works and inspect the logs.

---

## Getting Started

1. Clone the repository.
2. Install the required dependencies:
   - Install `Go` and `PostgreSQL` (for database handling).
   - Use `go get` to fetch the necessary Go modules.
   - Also look at example.sql for Database init.
3. Configure your network interfaces to monitor and connect your PostgreSQL database.
4. Run the application to begin monitoring and logging network traffic.

---

## Contribute

We welcome contributions to the project. If you're interested in improving the tool or adding new features, please feel free to open issues or pull requests.

### Contact
- Kaan Saydam: [kaannsaydamm@proton.me]
- Ata İlhan Köktürk: [atailhan2006@gmail.com]

---

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE.md) file for details.

