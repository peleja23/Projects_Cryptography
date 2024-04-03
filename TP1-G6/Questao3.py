from scapy.all import *
from scapy.layers.inet import IP, ICMP

def spoof_icmp(src_ip, dst_ip, interface):
    # Criar um objeto IP com o IP de origem forjado
    ip = IP(src=src_ip, dst=dst_ip)
    
    # Criar um pacote ICMP (echo request)
    icmp = ICMP()

    # Enviar o pacote na interface especificada
    send(ip/icmp, iface=interface)
    
    # Imprimir confirmação
    print(f"Pacote ICMP enviado de {src_ip} para {dst_ip} na interface {interface}")

if __name__ == "__main__":
    IP_ORIGEM = "192.168.126.1"
    IP_DESTINO = "8.8.8.8"
    INTERFACE = "Remote NDIS based Internet Sharing Device"
    
    # Execute a função spoof_icmp
    spoof_icmp(IP_ORIGEM, IP_DESTINO, INTERFACE)
