import scapy.all;
from scapy.all import *;
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("\n----------------------------------------------------------- W31C0m3 T0 5c@r13t ----------------------------------------------");
print("\tI am a Program who Gather's the active IP addresses and MAC (i.e.Hardware addresses) of connected Machines in LAN.");
print("\t USE : 1. To identify who is connected to network during Exam-Time");
print("\t       2. Best way identify a host is LIVE or DEAD (Without his/her knowledge)");
print("\t       3. ");
print("\t       4. ");
print("\t       5. ");

print("\t[*] Initializing modules");

for subnet_id in range(0,255):
	print "\t[*] Working For Subnet Address : 10.1."+str(subnet_id)+".*";
	print("\t\tIP ADDRESS\t\tHARDWARE ADDRESS");

	for host_id in range(0,255):	
		ip = "10.1."+str(subnet_id)+"."+str(host_id);
		arp_req_packet = ARP(pdst=ip);
		arp_res_packet = sr1(arp_req_packet,verbose=False);
		try:
			if arp_res_packet[0][0][0].hwsrc!="":
				print "\t\t",ip,"\t\t",arp_res_packet[0][0][0].hwsrc;
		except Exception, e:
			continue;
print("-----------------------------------------------------------------------------------------------------------------------------");