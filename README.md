# Distributed WPA2 Password Cracker

> A distributed, client-server C++ system that extracts the WPA2 4-way handshake from a `.cap` file, splits a wordlist across multiple cracking clients, and reports the password as soon as any client finds a match — all using raw sockets, OpenSSL cryptography, and multithreading.



## Ethical Use Notice

This tool is designed **exclusively for authorized penetration testing and educational research**. You must have **explicit written permission** from the network owner before using this tool on any Wi-Fi network. Unauthorized use is illegal under computer fraud laws in virtually every jurisdiction. The authors accept no liability for misuse.


## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#2-file-structure)
3. [Architecture Diagram](#3-architecture-diagram)
4. [WPA2 Cracking — How It Works](#4-wpa2-cracking--how-it-works)
   - [WPA2 4-Way Handshake Recap](#41-wpa2-4-way-handshake-recap)
   - [The Cracking Math](#42-the-cracking-math)
5. [Server — Deep Dive (server.cpp)](#5-server--deep-dive-servercpp)
   - [Packet Parsing](#51-packet-parsing)
   - [Handshake Extraction](#52-handshake-extraction)
   - [Client Coordination](#53-client-coordination)
   - [Thread Management & STOP Broadcast](#54-thread-management--stop-broadcast)
6. [Client — Deep Dive (client.cpp)](#6-client--deep-dive-clientcpp)
   - [Receiving the Handshake](#61-receiving-the-handshake)
   - [PMK Generation (PBKDF2)](#62-pmk-generation-pbkdf2)
   - [PTK Derivation (PRF-512)](#63-ptk-derivation-prf-512)
   - [MIC Verification](#64-mic-verification)
   - [Non-blocking STOP Detection](#65-non-blocking-stop-detection)
7. [Data Flow — End to End](#7-data-flow--end-to-end)
8. [Capture Files](#8-capture-files)
9. [Key Data Structures](#9-key-data-structures)
10. [Build Instructions](#10-build-instructions)
11. [How to Run](#11-how-to-run)
12. [Known Limitations & Improvements](#12-known-limitations--improvements)
13. [Key Concepts Tested](#13-key-concepts-tested)


## 1. Project Overview

Traditional WPA2 dictionary attacks run on a **single machine** — slow, hardware-bottlenecked, and non-scalable. This project addresses that by splitting the wordlist and distributing it:

- The **server** reads a `.cap` packet capture, extracts all the cryptographic material from the WPA2 4-way handshake (AP/client MACs, ANonce, SNonce, MIC, EAPOL frame), divides a wordlist into equal-sized chunks, and assigns one chunk to each connected client.
- Each **client** receives its chunk and the handshake data, then runs the full WPA2 key derivation (PBKDF2 → PRF-512 → HMAC-SHA1) independently on every password in its range.
- The moment any client finds the correct password it reports `FOUND:<password>` to the server, which immediately broadcasts a `STOP` command to all other clients — stopping wasted work.

The entire system is implemented in **C++ with Winsock2** (Windows) and **OpenSSL** for cryptographic operations.


## 2. File Structure


project/
│
├── server.cpp           # Server: pcap parsing, handshake extraction,
│                        #   client management, wordlist distribution
│
├── client.cpp           # Client: receives handshake + chunk,
│                        #   runs PMK→PTK→MIC crack loop
│
├── handshake-01.cap     # Sample pcap capture (reference/test file)
│
├── hammm1-07.cap        # Active capture file used in main()
│                        #   (SSID: HUAWEI-nK2M)
│
└── README.md            # This file
```

> **Note:** `T3.txt` (the wordlist) is referenced in `main()` but not included in the repository — you must supply your own wordlist file.

---

## 3. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         server.cpp                               │
│                                                                  │
│  ┌────────────────┐    ┌───────────────────────────────────────┐ │
│  │  .cap file     │───▶│  extractHandshakeParameters()         │ │
│  │ hammm1-07.cap  │    │  - parseCapturedPacket() per frame    │ │
│  └────────────────┘    │  - locate Beacon/ProbeResp → BSSID   │ │
│                        │  - locate M1 (AP→Client EAPOL)       │ │
│  ┌────────────────┐    │  - locate M2 (Client→AP EAPOL+MIC)   │ │
│  │  T3.txt        │    │  → HandshakeParameters struct         │ │
│  │  (wordlist)    │    └───────────────────────────────────────┘ │
│  └──────┬─────────┘                    │                         │
│         │ split into N chunks          │ hp (all fields)         │
│         ▼                              ▼                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              accept() loop (1 thread per client)         │   │
│  │                                                          │   │
│  │   handleClient(socket, hp, chunk)                        │   │
│  │   ├── sendHandshakeAndChunk() ─────────────────────────► │   │
│  │   └── recv() loop ◄── "FOUND:<pw>" or disconnect         │   │
│  └──────────────────────────────────────────────────────────┘   │
│         │                                                        │
│         │ on FOUND:  broadcastStop() → "STOP" → all sockets     │
└─────────┼────────────────────────────────────────────────────────┘
          │  TCP :9999
          │
┌─────────┼──────────────────────────────────────────────────────┐
│         ▼            client.cpp (N instances)                   │
│  receiveHandshakeAndPasswords()                                 │
│  ├── ap_mac, client_mac, anonce, snonce                         │
│  ├── captured_mic, eapol_frame, ssid                            │
│  └── passwords[] (this client's chunk)                          │
│                                                                 │
│  crackPasswords()                                               │
│  for each password in chunk:                                    │
│    ├── [non-blocking select()] check for "STOP"                 │
│    ├── generatePMK(password, ssid)  ← PBKDF2-SHA1 / 4096 iter  │
│    ├── customPRF512(pmk, A, B)      ← PRF-512 → 64-byte PTK    │
│    ├── HMAC-SHA1(ptk[0..15], eapol) → 16-byte computed MIC     │
│    └── if computed_MIC == captured_MIC                          │
│          send("FOUND:<password>")                               │
│          return                                                  │
└─────────────────────────────────────────────────────────────────┘


## 4. WPA2 Cracking — How It Works

### 4.1 WPA2 4-Way Handshake Recap

When a client connects to a WPA2 network, both sides run a **4-Way Handshake** to derive fresh session keys without transmitting the password over the air. The four EAPOL messages are:

| Message | Direction | Contains |
|---|---|---|
| **M1** | AP → Client | ANonce (random 32-byte nonce from AP) |
| **M2** | Client → AP | SNonce (random 32-byte nonce from Client) + **MIC** |
| **M3** | AP → Client | Encrypted GTK + MIC |
| **M4** | Client → AP | Acknowledgement |

This project captures **M1** (to get ANonce) and **M2** (to get SNonce + MIC). That is the minimum needed to verify a password candidate.

### 4.2 The Cracking Math

For each candidate password `P`:

```
1. PMK  = PBKDF2-HMAC-SHA1(P, SSID, iterations=4096, keylen=32)

2. B    = min(AP_MAC, Client_MAC) || max(AP_MAC, Client_MAC)
          || min(ANonce, SNonce) || max(ANonce, SNonce)
   A    = "Pairwise key expansion"

3. PTK  = PRF-512(PMK, A, B)           ← 64 bytes; first 16 = KCK

4. MIC_computed = HMAC-SHA1(KCK, EAPOL_M2_zeroed)[0:16]

5. if MIC_computed == MIC_captured  →  P is the correct password ✓
```

The ordering of MACs and nonces (min-before-max) is mandated by **IEEE 802.11** to ensure both sides derive identical keys regardless of which side computes first.

---

## 5. Server — Deep Dive (`server.cpp`)

### 5.1 Packet Parsing

```cpp
bool parseCapturedPacket(const uint8_t* packet, uint32_t caplen, Packet& pkt)
```

Parses raw 802.11 frames from the pcap capture:

- **Frame type 0, subtype 8** → Beacon frame → extracts SSID from tag ID 0
- **Frame type 0, subtype 5** → Probe Response → also extracts SSID
- **Frame type 2** → Data frame → checks LLC header for EtherType `0x888E` (EAPOL), extracts payload

The function also reads:
- `addr1` (bytes 4–9): destination MAC
- `addr2` (bytes 10–15): source MAC

QoS and DS flags are handled via `get80211HeaderLen()` to correctly skip the variable-length 802.11 header before reaching the LLC layer.

### 5.2 Handshake Extraction

```cpp
HandshakeParameters extractHandshakeParameters(const std::string& cap_file, const std::string& target_ssid)
```

Steps:
1. Opens the `.cap` file with **libpcap** (`pcap_open_offline`)
2. Iterates all frames — builds `ssid_to_bssid` map from Beacons and ProbeResponses
3. Collects all EAPOL frames into `eapolPackets`
4. Finds **M1**: first EAPOL frame where `addr2 == bssid` (AP is sender)
5. Finds **M2**: next EAPOL frame where `addr1 == bssid`, payload ≥ 97 bytes, and bytes [81:97] are **non-zero** (verifying the MIC field is populated)
6. Zeroes bytes [81:97] of M2 to produce `eapol_frame` (required by the MIC verification formula — the MIC field must be zero when computing the MIC)

Key offsets within an EAPOL-Key payload:

| Offset | Length | Field |
|---|---|---|
| 17 | 32 | ANonce (in M1) |
| 17 | 32 | SNonce (in M2) |
| 81 | 16 | MIC (in M2) |

### 5.3 Client Coordination

```cpp
void sendHandshakeAndChunk(SOCKET sock, const HandshakeParameters& hp, const vector<string>& chunk)
```

All binary fields are length-prefixed: a `uint32_t` byte count is sent before each blob, so the receiver knows exactly how many bytes to `recv`. Fields sent (in order):

1. `ap_mac` (6 bytes)
2. `client_mac` (6 bytes)
3. `anonce` (32 bytes)
4. `snonce` (32 bytes)
5. `captured_mic` (16 bytes)
6. `eapol_frame` (variable)
7. `ssid` (variable string)
8. Password chunk (all passwords joined by `\n`, sent as one blob)

### 5.4 Thread Management & STOP Broadcast

```cpp
void handleClient(SOCKET client_socket, const HandshakeParameters& hp, const vector<string>& chunk)
```

Each accepted client gets its own `std::thread` running `handleClient`. Two mutexes protect shared state:

| Mutex | Protects |
|---|---|
| `client_list_mutex` | `client_sockets` vector |
| `global_mutex` | `password_found` flag + `found_password` string |

When any thread receives `FOUND:<pw>`:
1. Sets `password_found = true` and stores the password (under `global_mutex`)
2. Calls `broadcastStop()` — iterates `client_sockets` and sends `"STOP"` to each

All other threads check `password_found` at the top of their `recv` loop and exit cleanly.

---

## 6. Client — Deep Dive (`client.cpp`)

### 6.1 Receiving the Handshake

```cpp
void receiveHandshakeAndPasswords(SOCKET sock, ...)
```

Mirror image of the server's sender. Uses a loop inside `receiveVector` to handle partial `recv` calls — TCP is a stream protocol and does not guarantee full messages arrive in one call:

```cpp
while (received < size) {
    int ret = recv(sock, vec.data() + received, size - received, 0);
    if (ret <= 0) throw std::runtime_error("...");
    received += ret;
}
```

The password chunk arrives as a single newline-delimited blob and is split via `std::istringstream`.

### 6.2 PMK Generation (PBKDF2)

```cpp
ByteVector generatePMK(const std::string& password, const std::string& ssid)
```

Uses OpenSSL's `PKCS5_PBKDF2_HMAC` with:
- Hash: SHA-1
- Iterations: **4096** (WPA2 standard)
- Output length: **32 bytes**
- Salt: the network SSID (as raw bytes)

This is the most computationally expensive step — 4096 SHA-1 rounds per password candidate. This is why distribution across multiple clients provides a meaningful speedup.

### 6.3 PTK Derivation (PRF-512)

```cpp
ByteVector customPRF512(const ByteVector& key, const std::string& A, const ByteVector& B)
```

Implements the WPA2 **Pseudo-Random Function** (IEEE 802.11 §11.6.1.2). Runs 4 HMAC-SHA1 iterations with an incrementing counter byte, concatenating all outputs into a 64-byte PTK:

```
for i in 0..3:
    input = A || 0x00 || B || i
    block[i] = HMAC-SHA1(PMK, input)
PTK = block[0] || block[1] || block[2] || block[3]   (64 bytes)
KCK = PTK[0:16]   (Key Confirmation Key — used for MIC)
```

The **B** vector is constructed as:
```
B = min(AP_MAC, Client_MAC) || max(AP_MAC, Client_MAC)
  || min(ANonce, SNonce) || max(ANonce, SNonce)
```
using lexicographic comparison (`isLessThan`) — both sides must build B identically or the keys will not match.

### 6.4 MIC Verification

```cpp
HMAC(EVP_sha1(), ptk.data(), 16,
     eapol_frame.data(), eapol_frame.size(),
     mic_res, &mic_len);
```

Computes HMAC-SHA1 over the zeroed EAPOL frame using the first 16 bytes of the PTK (KCK). The first 16 bytes of the result are compared against `captured_mic`. A match means the password is correct.

### 6.5 Non-blocking STOP Detection

Inside the crack loop, before each password attempt:

```cpp
fd_set readfds;
FD_ZERO(&readfds);
FD_SET(sock, &readfds);
timeval tv{ 0, 0 };   // zero timeout = purely non-blocking poll
if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
    // recv and check for "STOP"
}
```

`select` with a zero timeout acts as a **poll** — it does not block. If the server has sent `STOP`, the client reads it and exits immediately without waiting for its `recv` loop turn. This ensures fast cooperative shutdown.

---

## 7. Data Flow — End to End

```
1. Operator captures WPA2 handshake with airodump-ng → hammm1-07.cap

2. Server starts, opens .cap via libpcap
   └─ Parses 802.11 frames
      ├─ Beacons → SSID "HUAWEI-nK2M" → BSSID
      └─ EAPOL frames → M1 (ANonce), M2 (SNonce + MIC)

3. Server loads T3.txt wordlist → splits into N equal chunks

4. Server listens on TCP :9999, accepts N clients
   └─ For each client i:
      ├─ Sends: ap_mac, client_mac, anonce, snonce, captured_mic,
      │         eapol_frame (MIC zeroed), ssid, chunk[i]
      └─ Spawns thread → waits for FOUND: or disconnect

5. Each client independently runs:
   for password in chunk:
       PMK  = PBKDF2-HMAC-SHA1(password, ssid, 4096 iter)
       PTK  = PRF-512(PMK, "Pairwise key expansion", B)
       MIC  = HMAC-SHA1(PTK[0:16], eapol_frame)[0:16]
       if MIC == captured_MIC → send "FOUND:<password>"

6. Server receives FOUND:
   ├─ Logs the password
   ├─ Broadcasts STOP to all client sockets
   └─ All threads exit → join → server shuts down

7. Output: correct WiFi password printed to console
```

---

## 8. Capture Files

| File | Purpose |
|---|---|
| `handshake-01.cap` | Reference capture — used for testing the parser |
| `hammm1-07.cap` | Active capture used by `main()` — contains the 4-way handshake for SSID `HUAWEI-nK2M` |

Both are standard **pcap format** files (libpcap native format, not pcapng). They contain raw 802.11 frames captured in monitor mode.

> **How to capture your own:**
> ```bash
> sudo airodump-ng -c <channel> --bssid <AP_MAC> -w handshake wlan0mon
> # Optionally force a handshake:
> sudo aireplay-ng --deauth 5 -a <AP_MAC> wlan0mon
> ```

---

## 9. Key Data Structures

### `HandshakeParameters`

```cpp
struct HandshakeParameters {
    ByteVector  ap_mac;         // 6 bytes — BSSID of the access point
    ByteVector  client_mac;     // 6 bytes — MAC of the connecting device
    ByteVector  anonce;         // 32 bytes — random nonce from M1
    ByteVector  snonce;         // 32 bytes — random nonce from M2
    ByteVector  captured_mic;   // 16 bytes — MIC from M2 (the target)
    ByteVector  eapol_frame;    // Variable — M2 payload with MIC zeroed
    std::string ssid;           // Network name (used as PBKDF2 salt)
};
```

### `Packet`

```cpp
struct Packet {
    ByteVector  eapolPayload;   // Raw EAPOL bytes (after LLC header)
    std::string addr1, addr2;   // src/dst MACs as "XX:XX:XX:XX:XX:XX"
    std::string ssid;           // Extracted from Beacon/ProbeResp tag 0
    bool        isEAPOL;
    bool        isBeacon;
    bool        isProbeResp;
};
```

### Wire Protocol (Length-Prefixed Binary)

Every field sent over TCP is preceded by a 4-byte little-endian `uint32_t` giving the payload size. This lets the receiver allocate the exact buffer size and loop on `recv` until all bytes arrive — critical for correctness over TCP streams.

---

## 10. Build Instructions

### Prerequisites

| Dependency | Notes |
|---|---|
| MSVC or MinGW-w64 | C++17 or later |
| Winsock2 | Bundled with Windows SDK — `ws2_32.lib` |
| libpcap (Npcap) | npcap.com — install with "WinPcap API compatibility" mode |
| OpenSSL | 1.1.x or 3.x; link `libssl.lib` + `libcrypto.lib` |

### MSVC (Visual Studio)

```bat
:: Server
cl /std:c++17 /EHsc server.cpp ^
   /I "C:\npcap-sdk\Include" ^
   /I "C:\OpenSSL\include" ^
   /link ws2_32.lib ^
   "C:\npcap-sdk\Lib\x64\wpcap.lib" ^
   "C:\OpenSSL\lib\libssl.lib" ^
   "C:\OpenSSL\lib\libcrypto.lib" ^
   /out:server.exe

:: Client (no pcap needed)
cl /std:c++17 /EHsc client.cpp ^
   /I "C:\OpenSSL\include" ^
   /link ws2_32.lib ^
   "C:\OpenSSL\lib\libssl.lib" ^
   "C:\OpenSSL\lib\libcrypto.lib" ^
   /out:client.exe
```

### MinGW-w64

```bash
# Server
g++ -std=c++17 -o server.exe server.cpp \
    -I/c/npcap-sdk/Include \
    -I/c/OpenSSL/include \
    -L/c/npcap-sdk/Lib/x64 \
    -L/c/OpenSSL/lib \
    -lwpcap -lws2_32 -lssl -lcrypto

# Client
g++ -std=c++17 -o client.exe client.cpp \
    -I/c/OpenSSL/include \
    -L/c/OpenSSL/lib \
    -lws2_32 -lssl -lcrypto
```

---

## 11. How to Run

### Step 1 — Prepare Files

```
project/
├── server.exe
├── client.exe
├── hammm1-07.cap      ← your packet capture
└── T3.txt             ← your wordlist (one password per line)
```

### Step 2 — Edit `main()` in server.cpp if needed

```cpp
startServer(
    "hammm1-07.cap",   // ← path to your .cap file
    "HUAWEI-nK2M",     // ← target SSID
    "T3.txt",          // ← path to your wordlist
    2                  // ← number of clients you will connect
);
```

### Step 3 — Start the Server

```bat
server.exe
```

Expected output:
```
[*] Listening on port 9999, waiting for 2 clients...
[*] Found BSSID for SSID 'HUAWEI-nK2M': xx:xx:xx:xx:xx:xx
[+] Handshake extracted successfully
[*] Loaded 33149019 passwords
```

### Step 4 — Start Clients (separate terminals or machines)

```bat
client.exe
```

Each client prints progress every 25 passwords:
```
[*] Progress: 25/16574509 : Testing 'password123'
[*] Progress: 50/16574509 : Testing 'dragon2009'
```

### Step 5 — Result

```
[+] Password FOUND at attempt 7812: 'mywifi2023'
[*] Broadcasting STOP to all clients
[*] All threads joined. Password was found: mywifi2023
```

> **Running clients on different machines:** In `client.cpp`, change `"127.0.0.1"` in the `inet_pton` call to the server machine's IP address and rebuild.

---

## 12. Known Limitations & Improvements

### Current Limitations

| Issue | Detail |
|---|---|
| **Windows-only** | Uses Winsock2. Porting to Linux requires POSIX sockets. |
| **No client reconnect** | If a client crashes mid-run, its entire chunk is lost with no retry logic. |
| **No TLS on the wire** | Handshake data and passwords are sent in plaintext — a LAN observer could intercept the wordlist chunk. |
| **Fixed chunk size** | Chunks are pre-assigned at startup. If one client is faster, it sits idle while slower clients continue. |
| **`T3.txt` not included** | Must be sourced separately (e.g., rockyou.txt, SecLists). |
| **Single-pass M1/M2 detection** | The parser takes the very first valid M1 and M2 pair; a noisy capture with retransmissions could pick the wrong frames. |

### Suggested Improvements

- **Dynamic work stealing** — idle clients request more passwords rather than getting a fixed chunk upfront
- **TLS encryption** — `SSL_CTX` wrapping the socket so wordlist chunks and results are not readable on the LAN
- **Progress reporting** — clients periodically send `PROGRESS:<n>` so the server can display a live global completion percentage
- **Cross-platform support** — replace Winsock2 with Berkeley sockets + `#ifdef` guards
- **GPU acceleration** — replace the PBKDF2 loop with an OpenCL/CUDA kernel for orders-of-magnitude speedup on large wordlists

---

## 13. Key Concepts Tested

| Concept | Where it appears |
|---|---|
| **TCP socket programming** | `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, `recv()` in both files |
| **Length-prefixed binary protocol** | `sendVector` / `receiveVector` — `uint32_t` size prefix before every blob |
| **Multithreading** | `std::thread` per client; `std::mutex` for all shared state |
| **Race condition prevention** | `global_mutex` guards `password_found`; `client_list_mutex` guards the socket vector |
| **Non-blocking I/O** | `select()` with zero timeout used as a poll for the STOP signal inside the crack loop |
| **libpcap packet parsing** | `pcap_open_offline`, `pcap_next_ex`, raw 802.11 frame byte walking |
| **802.11 frame structure** | Type/subtype dispatch, variable header length (QoS, ToDS/FromDS), SSID IE tag parsing |
| **PBKDF2-HMAC-SHA1** | `PKCS5_PBKDF2_HMAC` — WPA2 PMK derivation (4096 iterations) |
| **PRF-512** | Custom IEEE 802.11 PRF using 4× HMAC-SHA1 rounds with counter byte |
| **HMAC-SHA1** | OpenSSL `HMAC(EVP_sha1(), ...)` — MIC computation and verification |
| **Cooperative shutdown** | `broadcastStop()` + client-side STOP polling for clean distributed termination |
| **Distributed workload splitting** | `chunk_size = passwords.size() / expected_clients` with remainder assigned to last client |

---

*README written for academic and security-research review. All testing was performed on networks owned by the authors.*
