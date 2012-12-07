/*
* this programe is working as plugin of netfilter 
* which block some special ipv6 and ipv4 packets
*/

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include "/usr/src/linux-headers-3.2.0-26-generic-pae/include/linux/netfilter_ipv4.h"
//#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <net/ipv6.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiu Jin");
MODULE_DESCRIPTION("Change the header of ipv6 packet");

static long int ip4addr = 0;
module_param(ip4addr, long, S_IRUGO);

#define PRINT(fmt,args...) printk("debug, " fmt, ##args)

/* IP6 Hooks */
/* After promisc drops#include <asm/byteorder.h>
, checksum checks. */
#define NF_IP6_PRE_ROUTING  0
/* If the packet is destined for this box. */
#define NF_IP6_LOCAL_IN     1
/* If the packet is destined for another interface. */
#define NF_IP6_FORWARD      2

/* Packets coming from a local process. */
#define NF_IP6_LOCAL_OUT        3
/* Packets about to hit the wire. */
#define NF_IP6_POST_ROUTING 4

void print_6addr(const struct in6_addr *addr)
{
    PRINT("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}


/*
* Hook deal with the the ipv6 packets, block specified address
*/
static unsigned int 
ip6_block(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*))
{
    struct sk_buff *sk = skb;
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);//header

    if(ip6_hdr->version == 6)
    {
        struct in6_addr destip = ip6_hdr->daddr;//destination ip
        //specify the ipv6 address that need block
        if(destip.s6_addr[0] == 0x20 && destip.s6_addr[1] == 0x01 && destip.s6_addr[2] == 0x0d && destip.s6_addr[3] == 0xa8 )
        {
            //if it match the condition then drop it
            PRINT("BLOCKED IP:");
            print_6addr(&destip);
            return NF_DROP;      
        }
        else
        {
            PRINT("PASS IP:");
            print_6addr(&destip);
        }
    }
    
    return NF_ACCEPT;      
}


/*
* Hook deal with the the ipv4 packets, block specified address
*/
static unsigned int 
ip4_block(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*))

{
    struct sk_buff *sk = skb;
	struct iphdr *ip4_hdr = ip_hdr(skb);//header

    if(ip4_hdr->version == 4)
    {
        //it was blocked, when visit 58.192.114.8
        //if(ip4_hdr->daddr == htonl(0x3ac07208))
if(ip4_hdr->daddr == htonl(ip4addr))
        {
            PRINT("BLOCKED!");
            PRINT("v4 address:%x\n",ip4_hdr->daddr);
            return NF_DROP;      
        }
    }  

    return NF_ACCEPT;    
}

/*Initialize the hook*/
static struct nf_hook_ops nf_out_block =
{
	.hook = ip6_block,
	.hooknum = NF_IP6_POST_ROUTING,
	.pf = PF_INET6,
	.priority = NF_IP6_PRI_FIRST,
};
static struct nf_hook_ops nf_out_4block =
{
	.hook = ip4_block,
	.hooknum = NF_IP6_POST_ROUTING,//acturally here is NF_IP_POST_ROUTING which value is 4
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

/*Initialize the module*/
static int __init ip6_block_init(void)
{
	int ret;
	//ret = nf_register_hook(&nf_out_block);
	ret = nf_register_hook(&nf_out_4block);
	PRINT("IPV6 block packet module init.\n");
	return 0; //success
}

/*Clear the module*/
static void __exit ip6_block_exit(void)
{
	//nf_unregister_hook(&nf_out_block);
	nf_unregister_hook(&nf_out_4block);
	PRINT("IPV6 block packet module exit.\n");
}

module_init(ip6_block_init);
module_exit(ip6_block_exit);
