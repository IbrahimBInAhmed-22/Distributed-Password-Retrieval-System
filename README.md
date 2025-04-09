# Distributed-Password-Retrirval-System
This program allows user to retrieve the password using ther concept of parallel activity and brute-force.
# Distributed WPA2 Password Cracker

## Abstract

This project presents a distributed system designed to efficiently crack WPA2 Wi-Fi passwords for **ethical penetration testing** purposes. The process begins with capturing a WPA2 4-way handshake using a compatible wireless adapter. Optionally, a deauthentication attack is performed to force a device to reconnect, thus capturing the handshake. After capturing the handshake, the server processes the data and extracts relevant fields. The server then distributes the password cracking workload by sending specific chunks of the password list to each connected client. This distributed approach minimizes cracking time and ensures scalability, enabling faster and more efficient password testing.

This tool is intended for educational purposes, to help students and professionals understand network security and assess the strength of WPA2 passwords in a legal and ethical context, only on networks for which they have explicit permission to test.

## Table of Contents

1. [Introduction](#introduction)
2. [Objectives](#objectives)
3. [Key Features](#key-features)
4. [System Components](#system-components)
5. [Technologies To Be Used](#technologies-to-be-used)
6. [Expected Outcome](#expected-outcome)
7. [Conclusion](#conclusion)
8. [Ethical Use](#ethical-use)
9. [How to Use](#how-to-use)

## Introduction

Cracking WPA2 passwords using a large wordlist is a computationally expensive and time-consuming process. Traditional methods, which rely on a single machine to process the entire wordlist, are often inefficient due to hardware limitations. This project proposes a solution by distributing the workload across multiple clients, each responsible for testing a subset of the password list. This approach significantly reduces the time required to crack WPA2 passwords by utilizing parallel processing.

This system can be used for ethical penetration testing, where the goal is to assess the strength of Wi-Fi passwords in a controlled and authorized manner. This project emphasizes the importance of responsible testing and adherence to legal and ethical guidelines in penetration testing.

## Objectives

- **Capture WPA2 Handshakes**: Use compatible tools like `airodump-ng` to sniff WPA2 handshakes from the wireless network.
- **Implement Deauthentication**: Optionally trigger WPA2 handshakes using a deauthentication attack (`aireplay-ng`).
- **Split the Password List**: Divide a large wordlist (around 33 million common passwords) into smaller, manageable chunks.
- **Distribute Password Chunks Among Clients**: Each client will receive a specific chunk of the wordlist along with the handshake data for processing.
- **Ensure Efficient Workload Distribution**: Prevent redundancy by ensuring that each client processes a unique subset of the password list.
- **Achieve Faster Cracking**: Leverage parallel processing to enhance the speed of cracking.

## Key Features

- **Handshake Capture**: Utilize tools like `airodump-ng` for sniffing WPA2 handshakes and `aireplay-ng` for deauthentication attacks to capture WPA2 handshakes.
- **Data Extraction**: Use `Scapy` to parse captured handshake packets on the server and extract relevant data like MAC addresses, nonces, and MICs.
- **Password Chunk Distribution**: The server splits the large password list into smaller chunks and sends them to the clients along with the extracted handshake data.
- **Smart Coordination**: The server tracks the status of each connected client and ensures efficient distribution of the password chunks.
- **Cracking Process**: Clients perform the cracking process locally by testing each password in their assigned range and validating the MIC.
- **Time Reporting**: Each client reports back to the server with the time taken to process its chunk, helping the server track progress.

## System Components

- **Splitter Script**: A Python script that splits a large merged wordlist (containing approximately 33 million passwords) into smaller, more manageable chunks.
- **Server**: The server extracts the handshake, compresses the password list, and coordinates the distribution of tasks to connected clients.
- **Clients**: The clients receive their assigned password chunks and the extracted handshake data, then perform the actual password cracking by testing each password in their assigned range.

## Technologies To Be Used

- **Python**: The core programming language used for implementing the system's logic and client-server communication.
- **Socket Programming**: To manage communication between the server and multiple clients.
- **Scapy**: A powerful Python library used for packet manipulation and parsing to extract handshake information.
- **Wireless Tools**: Such as `airodump-ng` for capturing WPA2 handshakes and `aireplay-ng` for deauthentication attacks.

## Expected Outcome

- A fully functional distributed WPA2 password cracking system.
- A significant reduction in cracking time due to parallel processing across multiple clients.
- The ability to support multiple clients, enabling scalability.
- A reliable and efficient system for cracking WPA2 passwords in a distributed manner.

## Conclusion

This project demonstrates a practical and efficient approach to WPA2 password cracking through a distributed architecture. By dividing the password cracking task across multiple clients, the system ensures faster processing, reduced time, and scalability. The implementation leverages parallel processing and efficient workload distribution, making it a valuable tool for password recovery in network security contexts.

## Ethical Use

This tool is designed for **ethical penetration testing** only. It should be used in the following contexts:

- **Authorized Network Testing**: Ensure you have explicit permission to test the network. Unauthorized testing or cracking of WPA2 passwords on networks you do not own or have permission to test is illegal and unethical.
- **Educational Purpose**: This system is intended for educational purposes to help students, researchers, and security professionals understand how WPA2 passwords can be cracked and to improve security defenses.
- **Penetration Testing Authorization**: Only perform penetration testing on networks that you own or have been granted explicit consent to test by the network owner or administrator.

The goal is to help improve security awareness and strengthen Wi-Fi networks through ethical and legal practices.

## How to Use

1. **Install Dependencies**: Ensure that Python 3.x is installed, and required libraries (`Scapy`, `socket`, etc.) are available.
   
2. **Set Up Server**: The server captures the WPA2 handshake and splits the password list. Once the handshake and list are prepared, the server will start distributing password chunks to connected clients.

3. **Run Clients**: Start the clients on different machines or on the same machine using different processes. Each client will receive a password chunk and start testing passwords locally.

4. **Monitor Progress**: The server will track the progress of each client and report the time taken for each password chunk.
