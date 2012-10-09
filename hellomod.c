//hello world
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/inet.h>
#include <net/ipv6.h>

#define PRINT(fmt,args...) printk("Marker: " fmt, ##args)
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)

#define NF_IP_POST_ROUTING 4

static unsigned int 
ip6_multi_modify(unsigned int hooknum,
				struct sk_buff **skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*))
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(*skb);//header
	struct in6_addr *destip = &ip6_hdr->daddr;//destination ip


	if(IN6_IS_ADDR_MULTICAST(destip))
	//if((destip)->s6_addr[0] == 0xff)
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


// static
static int __init hello_init(void)
{
	nf_register_hook(&nf_out_modify);
	PRINT("<1>Hello World module init\n");
	return 0;
}


static void __exit hello_exit(void)
{
	nf_unregister_hook(&nf_out_modify);
	PRINT("<1>Hello World module exit\n");
}

/*module initial and exit*/
module_init(hello_init);
module_exit(hello_exit);

/*module informations*/
MODULE_AUTHOR("Qiu Jin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hello Demo");
