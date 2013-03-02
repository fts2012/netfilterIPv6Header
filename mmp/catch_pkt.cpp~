/**
 * use libpcap catch packets
 *
 */
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<errno.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include <netinet/ip6.h>
#include "send_measure_info.cpp"

#include <string.h>

#define DEVICE_TYPE 2
#define ETH_SIZE 14
#define PACKET_SIZE 65535

struct ip6_dst_hdr
{
		uint8_t ip6d_nxt;
		uint8_t ip6d_len;
		uint8_t ip6d_opt_type;
		uint8_t ip6d_opt_len;
		uint32_t ip6d_ssn;
		uint32_t ip6d_sec;
		uint32_t ip6d_usec;
};

/* calcute the measure info items of new packet*/
int cnt =0;
char newpkt[PACKET_SIZE];

/*the ip address of this device*/
char device_ip[INET6_ADDRSTRLEN];

/**
 * filte the packets and send the informaiton to mcs
 * device type, device ip, send time, recv time, seq, group ip;
 * every 400 send a tcp packets
 */
void deal_with_pkt(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    //rules compare
    //if match rules store and transmit the content
    // 
    //if match rules store and transmit the content
printf("%d,",cnt);


    struct ip6_hdr * ipv6_hdr = (struct ip6_hdr*)(packet + ETH_SIZE); 
    //struct ipv6hdr * ip6_hdr = (struct ipv6_hdr*)(packet + sizeof(eth_hdr)); 
    struct in6_addr destip = ipv6_hdr->ip6_dst;//destination ip

    struct ip6_dst_hdr * nxthdr;
    char item[187];
    char  addr[INET6_ADDRSTRLEN];

    //TODO:condition
    //if(match ip rule) and destination header
    if(destip.s6_addr[0] == 0xff && destip.s6_addr[1] == 0x15 && ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 60)
    {

        //nxthdr =  (struct ip6_dst_hdr *)(packet + 40 + ETH_SIZE);
        //1,2001:da9:2324:1234:1243::1,12345678912134567,12345678912134567,555555,ff15:1234::2;
        //type, device ip, send ts ,recv ts, sequence, group ip
        inet_ntop(AF_INET6, &destip, addr, sizeof(addr));

        sprintf(item, "%s,%s,%ld:%ld,%ld:%ld,%d,%s;", DEVICE_TYPE, addr, nxthdr->ip6d_sec, nxthdr->ip6d_usec,(pkthdr->ts).tv_sec,(pkthdr->ts).tv_usec ,nxthdr->ip6d_ssn, device_ip);

        if(cnt <300)
        {
            strncat(newpkt, item, 187);//concat two string
            cnt++;  
        }else{
            // when the packets size is enough then send it to mcs
            sendmsg(newpkt);
            printf("content is :%s\n", newpkt);

            //clear for next measure info packet
            cnt = 0;
            // set zero
            memset(newpkt, 0, PACKET_SIZE);
        }

    }

}


/**
 * get the host ip
 */
/*
void getHostIpAddr()
{ 
    struct ifaddrs * ifAddrStruct=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);

    while (ifAddrStruct!=NULL) {
        if (ifAddrStruct->ifa_addr->sa_family==AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            printf("%s IP Address %s/n", ifAddrStruct->ifa_name, addressBuffer); 
        } else if (ifAddrStruct->ifa_addr->sa_family==AF_INET6) { // check it is IP6
            // is a valid IP6 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s/n", ifAddrStruct->ifa_name, addressBuffer); 
        } 
        ifAddrStruct=ifAddrStruct->ifa_next;
    }
    return 0;
}
*/

// consider one interface
int main(int argc,char *argv[])
{
    char *dev;
    char *net;
    char *mask;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct in_addr addr;

    //find a network device
    dev = pcap_lookupdev(errbuf);
    if(dev ==NULL)
    {
        printf("lookupdev error:%s\n",errbuf);
        exit(1);
    }

    //open the device
    // there is no need to look up all 65535, so we say 200
    pcap_t * device = pcap_open_live(dev, 200, 1, 0, errbuf);
    if(!device)
    {
        printf("pcap_open_live error:%s\n",errbuf);
        exit(1);
    }

    //construct a filter
    struct bpf_program filter;
    pcap_compile(device, &filter, "ip6 proto udp",1 , 0);//ipv6 packets and the protocal is udp
    pcap_setfilter(device, &filter);

    //wait 
//    int id =0 ;
    pcap_loop(device, -1, deal_with_pkt, NULL);

    pcap_close(device);

    return 0;
}
