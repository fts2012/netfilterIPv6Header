#ifndef CATCH_PKT_H
#define CATCH_PKT_H

#include <inttypes.h>
#include "common.h"

#define DEVICE_TYPE 2
#define ETH_SIZE 14
#define PACKET_SIZE 65535


/*The content to be added in the extend header in ipv6 packets
*/

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

void deal_with_pkt(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);


#endif
