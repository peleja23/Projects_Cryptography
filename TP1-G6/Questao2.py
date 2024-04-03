from scapy.all import *


inteface = "SAMSUNG Mobile USB Remote NDIS Network Device"
N_of_packets = 50
def print_pkt(pkt):
    pkt.show()



#Exercico 2.1
#pkt_arp = sniff(iface=inteface, filter='arp', count = N_of_packets) # Captura pacotes ARP 
#pkt_arp2 = sniff(iface=inteface, filter='arp', prn=print_pkt, count = N_of_packets) # Captura pacotes ARP e imprime
#wrpcap('Questao 2\ arp_packets.pcap', pkt_arp)

#Exercico 2.2
#pkt_tcp80 = sniff(iface=inteface, filter='tcp and dst port 80', count = N_of_packets) # Captura pacotes TCP destinados à porta 80
#wrpcap('Questao 2\ tcp80_packets.pcap', pkt_tcp80)

#Exercico 2.3
pkt_subnet = sniff(iface=inteface, filter='host 192.168.29.17', count = N_of_packets) # Captura pacotes da subrede
wrpcap('Questao 2\subnet_packets.pcap', pkt_subnet)