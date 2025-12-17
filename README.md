# TCP/IP Spoofing & Session Hijacking: The Mitnick Attack Simulation

This repository contains a full implementation of the **Kevin Mitnick Attack**, a historic exploit that leverages TCP Sequence Number Prediction and IP Spoofing to hijack a session. This project simulates the attack within a virtualized Docker environment, targeting the legacy **RSH (Remote Shell)** protocol.

##  Overview

The objective is to establish a spoofed TCP connection to a victim machine (X-Terminal) by impersonating a trusted server. Since RSH relies on IP-based trust, successfully spoofing the IP allows the attacker to inject a malicious payload.

### Key Concepts Demonstrated
- **SYN Flooding Simulation:** Silencing the real Trusted Server to prevent it from sending RST packets.
- **TCP Sequence Prediction:** Sniffing and predicting sequence numbers to complete the 3-Way Handshake without seeing the victim's packets.
- **RSH Protocol Exploitation:** Handling the unique requirement of RSH, which demands **two simultaneous TCP connections** to execute commands.
- **Backdoor Injection:** Modifying `.rhosts` to allow persistent, password-less access.

##  Environment & Tools

- **OS:** Ubuntu Linux (Seed Labs Docker Image)
- **Language:** Python 3
- **Libraries:** [Scapy](https://scapy.net/) (for packet manipulation)
- **Virtualization:** Docker & Docker Compose
- **Network Configuration:**
  - **Attacker:** `10.9.0.1`
  - **Victim (X-Terminal):** `10.9.0.5`
  - **Trusted Server:** `10.9.0.6`

##  Project Structure

- `task2_1.py`: Spoofs the **first TCP connection** (Handshake + RSH Command payload).
- `task2_2.py`: Spoofs the **second TCP connection** (Required by RSH for error reporting).

## ⚡ Step-by-Step Execution Guide

### 1. Initial Setup
Start the lab environment using Docker Compose:
```bash
sudo docker-compose up -d
