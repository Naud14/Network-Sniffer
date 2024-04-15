from scapy.all import *
import os


def Menu():
    PrintBanner()
    print("Welcome to this Network sniffer tool!\nUse this tool to capture and analyse network traffic!") 
    while True:
        print("\n- To start capuring network traffic, press 1 (+ enter)\n- To start analysing pcap files, press 2 (+ enter)\n- To exit this program, press 5 (+ enter)")
        user_input = int(input("Choice: "))
        if(user_input == 1):
            capture_packets()
        elif(user_input == 2):
            read_pcap_file()
        elif(user_input == 5):
            break
        else:
            print("Invalid input, please try again...")

def packet_handler(pkt):
    print(f"Packet captured -> more information: \n    {pkt.summary()}")

def capture_packets():
    os.system('clear')
    PrintBanner()
    print("Choose network interface from which packets should be captures\n    Think of 'eth0', 'enp0s3', 'wlan0', ect.")
    user_network_input = input("Choice: ")
    print("Choose amount of packets to capture (count)")
    user_count_input = int(input("Choice: "))
    print("Choose any optional filters\n    Think of 'tcp', 'udp', 'icmp', 'host 192.168.1.100', 'host 192.168.1.100 and port 80', ect.")
    user_filter_input = input("Choice: ")
    pcts = sniff(iface=user_network_input, count=user_count_input, prn=packet_handler, filter=user_filter_input)

    pcap_file = input("Enter the name of the pcap file to save: ")
    wrpcap(pcap_file + ".pcap", pcts)
    print(f"Packets saved to {pcap_file}")

def read_pcap_file():
    pcap_file = input("Enter the name of the pcap file to read: ")
    packets = rdpcap(pcap_file + ".pcap")
    print(f"Read {len(packets)} packets from {pcap_file}")
    for packet in packets:
        print(packet.summary())

def PrintBanner():
    print(r'''
    _      _____ _____  _      ____  ____  _  __   ____  _      _  _____ _____ _____ ____ 
    / \  /|/  __//__ __\/ \  /|/  _ \/  __\/ |/ /  / ___\/ \  /|/ \/    //    //  __//  __\
    | |\ |||  \    / \  | |  ||| / \||  \/||   /   |    \| |\ ||| ||  __\|  __\|  \  |  \/|
    | | \|||  /_   | |  | |/\||| \_/||    /|   \   \___ || | \||| || |   | |   |  /_ |    /
    \_/  \|\____\  \_/  \_/  \|\____/\_/\_\\_|\_\  \____/\_/  \|\_/\_/   \_/   \____\\_/\_\
    ''')

if __name__ == "__main__":
    os.system('clear')
    Menu()
