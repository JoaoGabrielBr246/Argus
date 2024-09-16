import socket
import struct

def translate_mac(bytes):
    return ":".join(map("{:02x}".format, bytes)).upper()

def ethernet_frame(data):
    dst_mac, src_mac, ethernet_type = struct.unpack("! 6s 6s H", data[:14])
    return translate_mac(dst_mac), translate_mac(src_mac), ethernet_type, data[14:]

def ip_header(data):
    ipheader = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ip_version = ipheader[0] >> 4
    ttl = ipheader[5]
    proto = ipheader[6]
    ip_src = ipheader[8]
    ip_dst = ipheader[9]
    return ip_version, ttl, proto, socket.inet_ntoa(ip_src), socket.inet_ntoa(ip_dst), data[20:]

def tcp_header(data):
    src_port, dst_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dst_port, sequence, acknowledgment, data[offset:]

def udp_header(data):
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    return src_port, dst_port, length, data[8:]

def protocol_description(proto):
    descriptions = {
        1: "ICMP: Protocolo de Controle de Mensagens da Internet - usado para mensagens de erro e diagnóstico.",
        6: "TCP: Protocolo de Controle de Transmissão - fornece comunicação confiável e orientada a conexão.",
        17: "UDP: Protocolo de Datagramas do Usuário - fornece comunicação rápida e não confiável.",
        4: "IP in IP: Encapsulamento de pacotes IP dentro de outros pacotes IP, usado para tunneling.",
        41: "IPv6: Protocolo de Internet versão 6 - nova versão do IP com melhorias sobre o IPv4.",
        50: "ESP: Encapsulated Security Payload - fornece criptografia e segurança para pacotes IP.",
        51: "AH: Authentication Header - fornece autenticação e integridade para pacotes IP.",
        0: "Protocolo 0: Não definido ou não utilizado para protocolos IP padrão."
    }
    return descriptions.get(proto, "Descrição não disponível")

if __name__ == "__main__":
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        data, source = s.recvfrom(65535)
        dst_mac, src_mac, tp, ip_pkt = ethernet_frame(data)
        ip_version, ttl, proto, ip_src, ip_dst, pkt_data = ip_header(ip_pkt)

        print("\n######## NOVO PACOTE CAPTURADO ########")
        
        print(f"\nEthernet Frame: {src_mac} -> {dst_mac}, Tipo: {hex(tp)}")
        print(f"IP Packet: {ip_src} -> {ip_dst}, Versão IP: {ip_version}, TTL: {ttl}, Protocolo: {proto}")

        print(f"Descrição do Protocolo: {protocol_description(proto)}")

        if proto == 1:
            print("Protocolo ICMP (1)")
            print(pkt_data)
            print("#########################################")
        elif proto == 6:
            src_port, dst_port, seq, ack, tcp_data = tcp_header(pkt_data)
            print(f"Protocolo TCP (6) - Porta Origem: {src_port}, Porta Destino: {dst_port}")
            print(f"Seq: {seq}, Ack: {ack}")
            print("#########################################")
        elif proto == 17:
            src_port, dst_port, length, udp_data = udp_header(pkt_data)
            print(f"Protocolo UDP (17) - Porta Origem: {src_port}, Porta Destino: {dst_port}, Tamanho: {length}")
            print(udp_data)
            print("#########################################")
