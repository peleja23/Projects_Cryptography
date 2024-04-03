from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

IP_DE_INTERESSE = "192.168.1.118"  # IP de origem que você quer detectar
IP_DESTINO_DE_INTERESSE = "8.8.8.8"  # IP de destino que você quer detectar
NOVO_IP_DE_ORIGEM = "192.168.1.100"  # Novo IP de origem que você quer definir
INTERFACE = "Remote NDIS based Internet Sharing Device"
MAX_PACOTES = 10  # Número máximo de pacotes a serem processados

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Verifique se o pacote atende aos critérios
        if ip_src == IP_DE_INTERESSE and ip_dst == IP_DESTINO_DE_INTERESSE:
            print(f"Pacote detectado de {ip_src} para {ip_dst}. Alterando IP de origem...")
            
            # Altere o IP de origem
            packet[IP].src = NOVO_IP_DE_ORIGEM

            
            # Delete os campos checksum para que Scapy os recompute
            del packet[IP].chksum
            if packet.haslayer(ICMP):
                del packet[ICMP].chksum
                
            # Reenvie o pacote
            sendp(packet, iface=INTERFACE)


if __name__ == "__main__":
    # Comece a escutar os pacotes
    sniff(filter=f"ip src {IP_DE_INTERESSE} and ip dst {IP_DESTINO_DE_INTERESSE}",iface=INTERFACE, prn=process_packet, store=0, count=MAX_PACOTES)
    print("Número máximo de pacotes processados. Encerrando...")
