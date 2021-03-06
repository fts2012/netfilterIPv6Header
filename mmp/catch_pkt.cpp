/**
 * use libpcap catch packets
 *
 */
#include "catch_pkt.h"

#include <string>
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<errno.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include <netinet/ip6.h>
#include "send_measure_info.h"
#include <string.h>
#include <libconfig.h++>

using namespace std;
using namespace libconfig;


/* calcute the measure info items of new packet*/
int cnt = 0;
char newpkt[PACKET_SIZE];

/*the ip address of this device*/
char device_ip[INET6_ADDRSTRLEN];

/*share memory id*/
int shm_id =0;

/* send message */
MessageHandler *mh =NULL;
/**
 * filte the packets and send the informaiton to mcs
 * device type, device ip, send time, recv time, seq, group ip;
 * every 400 send a tcp packets
 */
void deal_with_pkt(u_char *arg, const struct pcap_pkthdr *pkthdr,
		const u_char *packet) {

	struct ip6_hdr * ipv6_hdr = (struct ip6_hdr*) (packet + ETH_SIZE);
	struct in6_addr destip = ipv6_hdr->ip6_dst; //destination ip

	struct ip6_dst_hdr * nxthdr;
	char item[187];
	char addr[INET6_ADDRSTRLEN];

//cout<<ipv6_hdr->ip6_nxt<<endl;
	//if match rules store and transmit the content
	//if(match ip rule) and destination header
//    if(destip.s6_addr[0] == 0xff && destip.s6_addr[1] == 0x15 && ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 60)
	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 60 && match_rule(shm_id, &destip)) {
		nxthdr =  (struct ip6_dst_hdr *)(packet + 40 + ETH_SIZE);
		//1,2001:da9:2324:1234:1243::1,12345678912134567,12345678912134567,555555,ff15:1234::2;
		//992 bit
		//type, device ip, send ts ,recv ts, sequence, group ip
		inet_ntop(AF_INET6, &destip, addr, sizeof(addr));

//		sprintf(item, "%d,%s,%ld:%ld,%ld:%ld,%d,%s;", DEVICE_TYPE, device_ip,
//				nxthdr->ip6d_sec, nxthdr->ip6d_usec, (pkthdr->ts).tv_sec,
//				(pkthdr->ts).tv_usec, nxthdr->ip6d_ssn, addr);
//
		sprintf(item, "%d,%s,%u,%u,%u,%u,%u,%s;", DEVICE_TYPE, device_ip,
				ntohl(nxthdr->ip6d_sec), ntohl(nxthdr->ip6d_usec), (pkthdr->ts).tv_sec,
				(pkthdr->ts).tv_usec, ntohl(nxthdr->ip6d_ssn), addr);

		if (cnt < 60) {
			strncat(newpkt, item, sizeof(item)); //concat two string
			cnt++;
		} else {
			// when the packets size is enough then send it to mcs
			// use multiple thread
			mh->sendmsg(newpkt);
			//printf("content is :%s\n", newpkt);
			printf("content is :%s\n", "test");

			//clear for next measure info packet
			cnt = 0;
			// set zero
			memset(newpkt, 0, PACKET_SIZE);
		}

	}

}

// consider one interface
int main(int argc, char **argv) {
	char *dev;
	char *net;
	char *mask;
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr;

	char file_shm[20];
	int size_of_shm;
	//string ifname;

	Config cfg;
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile("mmp_ini.cfg");
	} catch (const FileIOException &fioex) {
		std::cerr << "I/O error while reading file." << std::endl;
		return (EXIT_FAILURE);
	} catch (const ParseException &pex) {
		std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
				<< " - " << pex.getError() << std::endl;
		return (EXIT_FAILURE);
	}
	try {
		strcpy(device_ip, cfg.lookup("device_ip").c_str());
		strcpy(file_shm, cfg.lookup("file_shm").c_str());
		size_of_shm = cfg.lookup("size_of_shm");
		//ifname = cfg.lookup("iterface_name");

		string mcs_ip = cfg.lookup("mcs_ip");
		int mcs_port = cfg.lookup("mcs_port");
		MessageHandler temph(mcs_ip, mcs_port);
		mh = new MessageHandler(mcs_ip, mcs_port);

	} catch (const SettingNotFoundException &nfex) {
		std::cerr << "No 'name' setting in configuration file." << std::endl;
	}

	int size = 50;
	shm_id = create_shm(file_shm, size_of_shm);
	if (shm_id == 0)
		return 0;

	//find a network device
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		printf("lookupdev error:%s\n", errbuf);
		exit(1);
	}

	//open the device
	// there is no need to look up all 65535, so we say 200
	pcap_t * device = pcap_open_live(dev, 200, 1, 0, errbuf);
	if (!device) {
		printf("pcap_open_live error:%s\n", errbuf);
		exit(1);
	}

	//construct a filter
	struct bpf_program filter;
	//ipv6 packets and the protocal is udp
	pcap_compile(device, &filter, "ip6 proto udp", 1, 0);
	pcap_setfilter(device, &filter);

	//wait
//    int id =0 ;
	pcap_loop(device, -1, deal_with_pkt, NULL);

	pcap_close(device);

}
