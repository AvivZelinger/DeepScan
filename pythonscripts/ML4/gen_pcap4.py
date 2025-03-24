#!/usr/bin/env python3
"""
This script generates a PCAP file using Scapy based on the BProtocol defined in bprotocol_db.py.
BProtocol fields:
  1. header         : 4 bytes, char, constant ('BPRT')
  2. version        : 4 bytes, int (random between 1 and 5)
  3. flags1         : 1 byte, bitfield (random value 0-255)
  4. flags2         : 1 byte, bitfield (random value 0-255)
  5. temperature    : 4 bytes, float (IEEE 754)
  6. pressure       : 8 bytes, double (IEEE 754)
  7. device_id      : 10 bytes, char (random alphanumeric)
  8. message_length : 4 bytes, int (random between 5 and 20)
  9. message        : Dynamic field, char (length defined by message_length)
  10. checksum      : 4 bytes, int (random value)
"""

from scapy.all import IP, UDP, Raw, wrpcap
import random
import time
import string
import struct

# List of example source IP addresses for BProtocol
ENDPOINTS = ["192.168.50.1", "192.168.50.2", "192.168.50.3", "192.168.50.4"]

def rand_flags():
    positions = random.sample(range(8), 4)
    result = 0
    # Set the bits at the chosen positions to 1
    for pos in positions:
        result |= (1 << pos)
    return result 

def create_bpayload():
    # Field 1: header (constant 'BPRT')
    header = b'BPRT'
    
    # Field 2: version (4 bytes int, random between 1 and 5)
    version = random.randint(1, 5)
    version_bytes = version.to_bytes(4, byteorder='big')
    
    # Field 3: flags1 (1 byte, bitfield, random 0-255)
    flags1 = rand_flags()
    flags1_bytes = flags1.to_bytes(1, byteorder='big')
    
    # Field 4: flags2 (1 byte, bitfield, random 0-255)
    flags2 = rand_flags()
    flags2_bytes = flags2.to_bytes(1, byteorder='big')
    
    # Field 5: temperature (4 bytes, float)
    temperature = random.uniform(-50.0, 150.0)  # for example, in Celsius
    temperature_bytes = struct.pack('!f', temperature)
    
    # Field 6: pressure (8 bytes, double)
    pressure = random.uniform(950.0, 1050.0)  # example atmospheric pressure in hPa
    pressure_bytes = struct.pack('!d', pressure)
    
    # Field 7: device_id (10 bytes, random alphanumeric string)
    device_id_str = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    device_id_bytes = device_id_str.encode('utf-8')
    
    # Field 8: message_length (4 bytes, int, random between 5 and 20)
    message_length = random.randint(5, 20)
    message_length_bytes = message_length.to_bytes(4, byteorder='big')
    
    # Field 9: message (dynamic, random alphanumeric string of length message_length)
    message_str = ''.join(random.choices(string.ascii_letters + string.digits, k=message_length))
    message_bytes = message_str.encode('utf-8')
    
    # Field 10: checksum (4 bytes, int, random value between 0 and 2^32-1)
    checksum = random.randint(0, 4294967295)
    checksum_bytes = checksum.to_bytes(4, byteorder='big')
    
    # Combine all fields in order
    payload = (header + version_bytes + flags1_bytes + flags2_bytes +
               temperature_bytes + pressure_bytes + device_id_bytes +
               message_length_bytes + message_bytes + checksum_bytes)
    return payload

def generate_bpcap(file_name, num_packets=100):
    packets = []
    for _ in range(num_packets):
        payload = create_bpayload()
        # Choose a random source IP from the list; use a fixed destination IP (e.g., 192.168.60.100)
        src_ip = random.choice(ENDPOINTS)
        pkt = IP(src=src_ip, dst="192.168.60.100") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"PCAP file '{file_name}' created with {num_packets} packets from addresses: {ENDPOINTS}")

if __name__ == '__main__':
    generate_bpcap("test_24_3.pcap", num_packets=100)
