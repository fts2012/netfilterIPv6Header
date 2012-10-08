/*
* this programe is working as plugin of netfilter which will pin a timestamp to
* the destination header of ipv6 packet every x seconds when the packet is 
* the object multicast packet.
*/


#include <linux/netfilter.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/ipv6.h>
//#include <netinet6/in6.h>
//#include <sys/time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiu Jin");
MODULE_DESCRIPTION("Change the header of ipv6 packet");

#define PRINT(fmt,args...) printk("Marker: " fmt, ##args)


#define NF_IP_PRE_ROUTING        0
#define NF_IP_LOCAL_IN        1
#define NF_IP_FORWARD  2
#define NF_IP_LOCAL_OUT         3
#define NF_IP_POST_ROUTING 4

/*sequence of measeure sample packet*/
static int sample_seq = 0;

/*Next header destination header*/
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


struct sk_buff *
ip6_encapsulate_pkt(struct sk_buff **skb)
{
	struct sk_buff *new_skb, *temp_skb;
	struct ipv6hdr * ip6_hdr = ipv6_hdr(*skb);
	struct ip6_dst_hdr *ip6_dst;
	struct timeval tv;//get time

	temp_skb = *skb;
	ip6_hdr->nexthdr = 0x60;//set next header as 60 which means next destination header.

	//copy from the *skb to new_skb
	new_skb = skb_copy_expand(*skb, skb_headroom(*skb),
				skb_tailroom(*skb) + sizeof(struct ip6_dst_hdr),
				GFP_ATOMIC);
	if(new_skb == NULL)
	{
		PRINT("Allocate new sk_buffer error!\n");
		//if error happens ,will free the last struct cause any problem?
		//kfree_skb(temp_skb);
		return NULL;
	}

	//set the new_skb
	if(temp_skb->sk != NULL)
		skb_set_owner_w(new_skb, temp_skb->sk);

	//move tail to tail + sizeof(ip6_dst_hdr)
	skb_put(new_skb,sizeof(struct ip6_dst_hdr));
  
	//insert a ip6_dst_hdr between the memory
	memcpy (new_skb->data, temp_skb->data, 40);//assume that the ip header has 40 bytes
    	memcpy (new_skb->data + 40 + sizeof (struct ip6_dst_hdr),
			          temp_skb->data + 40, temp_skb->len - 40);


	//release the old struct
	kfree_skb(temp_skb);

	skb = &new_skb;//skb pointer to new_skb

	ip6_dst = (struct ip6_dst_hdr *)(new_skb->data + 40);
	//add ipv6 destination header
	ip6_dst->ip6d_nxt = IPPROTO_UDP;
	ip6_dst->ip6d_len = 0x01;
	ip6_dst->ip6d_opt_type = 0x15;// type of option
	ip6_dst->ip6d_opt_len =  0x0C;
	//TODO:sys/time.h cant't find
	//gettimeofday(&tv, NULL);
	//ip6_dst->ip6d_sec =x(2.4.21-37.EL htonl(tv.tv_sec);
	//ip6_dst->ip6d_usec = htonl(tv.tv_usec);
	sample_seq++;
	if(sample_seq==0xffffffff)//if overflow ，reset
	{
	   sample_seq=0;
	}
	ip6_dst->ip6d_ssn = htonl(sample_seq);

	//checksum, ipv6 dose not have a checksum part

	return *skb;
}


/*Hook which will call the encapsulate func when condition satisfied
 *condition1: IPv6 Multicast packets
 *condition2: every 20ms
 */
static unsigned int 
ip6_multi_modify(unsigned int hooknum,
				struct sk_buff **skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*))
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(*skb);//header
	struct in6_addr *destip = &ip6_hdr->daddr;//destination ip


	//if(IN6_IS_ADDR_MULTICAST(destip))
	if((destip)->s6_addr[0] == 0xff)
	{
		//if the packet is a multicast packet
		//find the next destination header and change it
		//add a header to exist memory space more call crack
		//so encapulate a new sk_buff with the original data and new header
	//	ip6_encapsulate_pkt(skb);
	//	if(!*skb)
	//		return NF_STOLEN;//?
	PRINT("multicast packet!");

	}
	return NF_ACCEPT;
}


/*Initialize the hook*/
static struct nf_hook_ops nf_out_modify =
{
	.hook = ip6_multi_modify,
	.hooknum = NF_IP_POST_ROUTING,//Check all the forwarded packets
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

/*Initialize the module*/
static int __init ip6_multi_init(void)
{
	int ret;
	ret = nf_register_hook(&nf_out_modify);
	PRINT("IPV6 multicast packet modify module init.\n");
	return 0; //success
}

/*Clear the module*/
static void __exit ip6_multi_exit(void)
{
	nf_unregister_hook(&nf_out_modify);
	PRINT("IPV6 multicast packet modify module exit.\n");
}

module_init(ip6_multi_init);
module_exit(ip6_multi_exit);
