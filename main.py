from hashlib import md5
from binascii import unhexlify
import pyshark
import re
from scapy.all import rdpcap
import argparse
import colorama
from pyfiglet import Figlet
import os

def get_hex_value(packet):
    try : 
        layers = packet.layers
        ospf_layer = layers[2]
        ospf_elements = ospf_layer._all_fields
        final_string = ""
        ospf_values = list(ospf_elements.values())[-9:]
        final_string = ospf_values[0][-4:] + str(int(int(ospf_values[1]) / 4) * 1000)[::-1] + '0' * 3 + ospf_values[2] + '0' * 3 + ospf_values[3] + ospf_values[4][-8:]
        ospf_elements[1] = int(int(ospf_values[1]) / 4) * 1000
        ospf_elements[1] = str(ospf_elements[1])[::-1]
        ospf_elements[2] = '0' * 3 + ospf_values[2]
        ospf_elements[3] = '0' * 3 + ospf_values[3]
        final_string += '0002' + '0014'
        final_string += ospf_values[7][-8:]
        return final_string
    except:
        print("Error in packet")
        return None

def isolate_auth_data(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    filtered_packets = [packet for packet in cap if 'ospf' in packet]
    print("========================================")
    print("Found {X} packets".format(X=len(filtered_packets)) + " in the file " + pcap_file)
    print("========================================\n")
    packets = []
    for packet in filtered_packets:
        packet_str = str(packet)
        hash_line = packet_str.splitlines()[-6]
        auth_data = hash_line.split()[3]
        packets.append(auth_data)
    cap.close()
    return packets

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    f = Figlet(font='slant')
    print(f.renderText('OSPF Cracker by M58'))
    colorama.init()
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", required=True, help="pcap file to crack")
    parser.add_argument("-w", "--wordlist", required=True, help="wordlist to use")
    args = parser.parse_args()
    pcap_file_path = args.pcap
    capture = pyshark.FileCapture(pcap_file_path)
    for packet in capture:
        packet_tobf = get_hex_value(packet)
        break
    capture.close()
    auth_data_packets = isolate_auth_data(pcap_file_path)
    expected = auth_data_packets[0]
    print("Expected hash:", expected)
    print("Packet to bruteforce:", packet_tobf)
    print("\n")


    expected = unhexlify(expected)
    data = unhexlify(packet_tobf)

    with open(args.wordlist, "rb") as f:
        for line in f:
            key = line.strip()[:16]
            if len(key) < 16:
                key = key + b"\x00" * (16 - len(key))
            res = md5(data + key).digest()
            if res == expected:
                print("=====================================")
                print(colorama.Fore.GREEN + "Found password:", line.strip().decode())
                print(colorama.Fore.WHITE)
                print("=====================================")
                break


if __name__ == "__main__":
    main()
