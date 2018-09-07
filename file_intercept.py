"""This code converts the packet flowing through a computer to a scapy packet, and allows us the read
and modify the code"""

import scapy.all as scapy
import netfilterqueue

def process_packet(packet):

	#Step1 : To convert the packet into a scapy packet

	scapy_packet = scapy.IP(packet.get_payload())

	if scapy_packet.haslayer(scapy.Raw):

		if scapy_packet[scapy.TCP].dport == 80:
			print("[+] HTTP Request")
		elif scapy_packet[scapy.TCP].sport == 80:
			print("[+] HTTP Response")

	packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()