# Distributed WPA2 Password Retrieval System (C++)

A high-performance, distributed C++ application designed to recover WPA2-PSK passwords by parallelizing the 4-way handshake verification process across multiple network nodes.

## 🚀 Technical Highlights
- **Manual Packet Parsing:** Uses `WinPcap` to parse raw IEEE 802.11 frames and extract EAPOL handshake parameters (MACs, Nonces, MIC).
- **Custom Crypto Implementation:** Implements the WPA2 key derivation function (KDF) using OpenSSL, including PBKDF2-HMAC-SHA1 and PRF-512.
- **Distributed Architecture:** A centralized server partitions massive wordlists and distributes them to C++ client workers via Winsock2 TCP/IP sockets.
- **Asynchronous Control:** Clients use non-blocking I/O (`select`) to listen for a "STOP" signal from the server the moment another node finds the match, saving CPU cycles.

## 🛠 Tech Stack
- **Language:** C++17
- **Libraries:** OpenSSL (Crypto), WinPcap/Npcap (Packet Capture), Winsock2 (Networking)
- **Concepts:** Parallel Computing, Socket Programming, Network Security, IEEE 802.11 Protocol.

## 📂 Project Structure
- `server.cpp`: Handles `.cap` file parsing, wordlist chunking, and client orchestration.
- `client.cpp`: Receives handshake data, generates PMKs/PTKs, and performs the brute-force computation.

## 🔧 Prerequisites
- OpenSSL 3.x
- Npcap SDK
- Windows (Winsock2)

## ⚖️ Ethical Use
This tool is for educational and authorized penetration testing only. Use only on networks you own or have explicit permission to test.
