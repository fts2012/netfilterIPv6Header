/*
* this programe is working as plugin of netfilter which will pin a timestamp to
* the destination header of ipv6 packet every x seconds when the packet is 
* the object multicast packet.
*/


#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
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
#include <linux/time.h>

#include <asm/byteorder.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiu Jin");
MODULE_DESCRIPTION("Change the header of ipv6 packet");

#define PRINT(fmt,args...) printk(", " fmt, ##args)


/* IP6 Hooks */
/* After promisc drops
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


/*sequence of measeure
 sample packet*/
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


inline
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
 char *in_ntoa(__u32 in)
  {
          static char buff[18];
          char *p;
  
          p = (char *) &in;
          sprintf(buff, "%d.%d.%d.%d",
                  (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
          return(buff);
  }


struct sk_buff *
ip6_reconstruct_ori_pkt(struct sk_buff *skb)
{
	struct ipv6hdr * ip6_hdr = ipv6_hdr(skb);
	struct ip6_dst_hdr *ip6_dst;
	struct timeval tv;//get time
    int i =0;
    int extend_len = sizeof(struct ip6_dst_hdr);
	ip6_hdr->nexthdr = 0x3c;//set next header as 60 which means next destination header.
    ip6_hdr->payload_len =  htons(ntohs(ip6_hdr->payload_len) + extend_len);
PRINT("%u,%u,%u\n",skb->data,skb->data+40,skb->data+skb->len);
	//move tail to tail + sizeof(ip6_dst_hdr)
PRINT("TRUESIZE:%d,len:%d,%d\n",skb->truesize,skb->len,skb->data_len);
	skb_put(skb, sizeof(struct ip6_dst_hdr));
    skb->truesize += sizeof(struct ip6_dst_hdr);
PRINT("TRUESIZE:%d,len:%d,%d\n",skb->truesize,skb->len,skb->data_len);


	//insert a ip6_dst_hdr between the memory

for(i = skb->data; i <= skb->data + skb->len -20; i = i+4)
{
    PRINT("%x",htonl(*(long *)(i)));
}
PRINT("%u,%u,%u\n",skb->data,skb->data+40,skb->data+skb->len);
    //memcpy (skb->data + 40 + sizeof (struct ip6_dst_hdr),
	//		          skb->data + 40, skb->len - 56);//for the length of skb is increased 16, so we should minus 16+40 to get the left content

    //copy memory in one space,like move from the top to the bottom
    int begin = skb->data + 40;
    int end = skb->data + skb->len -16;
    for(i = end; i-begin >=16; i=i-16)
    {
    memcpy(i,i-16,16);
    }
    if(i-begin>0)
        memcpy(begin+16,begin,i-begin);


//PRINT("HEADER after copy, %x\n",*(long *)(skb->data + 40+ sizeof (struct ip6_dst_hdr)));
for(i = skb->data; i <= skb->data + skb->len -4; i = i+4)
{
    PRINT("%x",htonl(*(long *)(i)));
}
PRINT("\n");

    //turn the space to ip6_dst struct
	ip6_dst = (struct ip6_dst_hdr *)(skb->data + 40);
    memset(ip6_dst,0,sizeof(struct ip6_dst_hdr));//clear
	//add ipv6 destination header
	ip6_dst->ip6d_nxt = 0x11;
	ip6_dst->ip6d_len = 0x01;
	ip6_dst->ip6d_opt_type = 0x15;// type of option
	ip6_dst->ip6d_opt_len = 0x0c;

	do_gettimeofday(&tv);
	//ip6_dst->ip6d_sec =x(2.4.21-37.EL htonl(tv.tv_sec);
    ip6_dst->ip6d_sec = htonl(tv.tv_sec);
	ip6_dst->ip6d_usec = htonl(tv.tv_usec);
	sample_seq++;
	if(sample_seq==0xffffffff)//if overflow ，reset
	{
	   sample_seq=0;
	}
	ip6_dst->ip6d_ssn = htonl(sample_seq);
for(i = skb->data; i <= skb->data + skb->len -4; i = i+4)
{
    PRINT("%x",htonl(*(long *)(i)));
}

	return skb;
}

struct sk_buff *
ip6_reconstruct_copy_pkt(struct sk_buff *skb)
{
	struct sk_buff *new_skb, *temp_skb;
	struct ipv6hdr * ip6_hdr = ipv6_hdr(skb);
	struct ip6_dst_hdr *ip6_dst;
	struct timeval tv;//get time
    int extend_len = sizeof(struct ip6_dst_hdr);

	ip6_hdr->nexthdr = 0x3c;//set next header as 60 which means next destination header.
    ip6_hdr->payload_len =  htons(ntohs(ip6_hdr->payload_len) + extend_len);
	//copy from the *skb to new_skb
	new_skb = skb_copy_expand(skb, skb_headroom(skb),
				skb_tailroom(skb) + extend_len,
				GFP_ATOMIC);

	if(new_skb == NULL)
	{
		PRINT("Allocate new sk_buffer error!\n");
		//FIXME:if error happens ,will free the last struct cause any problem?
		//kfree_skb(skb);
		return NULL;
	}

	//set the new_skb
	if(skb->sk != NULL)
		skb_set_owner_w(new_skb, skb->sk);

	//move tail to tail + sizeof(ip6_dst_hdr)
	skb_put(new_skb,extend_len);
    
	//insert a ip6_dst_hdr between the memory
	memcpy (new_skb->data, skb->data, 40);//assume that the ip header has 40 bytes

    memcpy (new_skb->data + 40 + sizeof (struct ip6_dst_hdr),
			          skb->data + 40, skb->len - 40);

	//release the old struct
    //call kfree_skb will crash the system, so here use a compromise way to drop the old skb in 
	//kfree_skb(skb);

	skb = new_skb;//skb pointer to new_skb

    //turn the space to ip6_dst struct
	ip6_dst = (struct ip6_dst_hdr *)(skb->data + 40);
    memset(ip6_dst,0,extend_len);//clear
	//add ipv6 destination header
	ip6_dst->ip6d_nxt = 0x11;
	ip6_dst->ip6d_len = 0x01;
	ip6_dst->ip6d_opt_type = 0x15;// type of option
	ip6_dst->ip6d_opt_len = 0x0c;
	do_gettimeofday(&tv);
	//ip6_dst->ip6d_sec =x(2.4.21-37.EL htonl(tv.tv_sec);
    ip6_dst->ip6d_sec = htonl(tv.tv_sec);
	ip6_dst->ip6d_usec = htonl(tv.tv_usec);

	sample_seq++;
	if(sample_seq==0xffffffff)//if overflow ，reset
	{
	   sample_seq=0;
	}
	ip6_dst->ip6d_ssn = htonl(sample_seq);

	return skb;
}


/*Hook which will call the encapsulate func when condition satisfied
 *condition1: IPv6 Multicast packets
 *condition2: every 20ms
 */
static unsigned int 
ip6_multi_modify(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*))
{
    struct sk_buff *sk = skb;
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);//header

//because nh only supportted in kernels below 2.6
//after 2.6, it often use network_header to express nh
//struct ipv6hdr *ip6_hdr = (struct ipv6hdr*)skb->nh.ipv6h;

if(ip6_hdr->version == 6)
{
    struct in6_addr destip = ip6_hdr->daddr;//destination ip
    //TODO:use module_para or /proc to replace here
//PRINT("DEST ip : %x,%x",(&destip)->s6_addr[0],(&destip)->s6_addr[1]);
    if(destip.s6_addr[0] == 0xff && destip.s6_addr[1] == 0x15)
    //FIXME:find where ipv6_addr_is_multicast belongs to
    //if(ipv6_addr_is_multicast(&ip6_hdr->daddr))
    {
//FIXME:The size of tail room
       /* if(skb_tailroom(sk) >= 40)
        {
            PRINT("tailroom is enough\n");
            skb = ip6_reconstruct_ori_pkt(skb);
        }
        else
        {*/
           // if(ip6_hdr->nexthdr == 0x11){
        
        if(ip6_hdr->nexthdr != 0x3c){
            //if the next header is no 60 that is this packet was not reconstructed
            skb = ip6_reconstruct_copy_pkt(skb);
            ip_route_me_harder(skb,RTN_LOCAL);
            okfn(skb);  
            //drop the old skb
            return NF_STOLEN;
        }
        //        PRINT("not enough\n");
        //    }
        //}
//print before change
//skb = ip6_encapsulate_pkt_t(skb);
        if(skb == NULL)
        {
            PRINT("Allocate new sk_buffer error!\n");
            return NF_STOLEN;
        }


        if(!skb)
            return NF_STOLEN;
        //print_6addr(&ip6_hdr->daddr);
    }
/*
    else
    {
//        PRINT("normal dest:%s",in6_ntoa(&ip6_hdr->daddr));
        print_6addr(&ip6_hdr->daddr);
    }
    PRINT("DEST ip : %x",(&destip)->s6_addr[0]);
*/
}

/*else if(ip6_hdr->version == 4)
{
//what I caught are all ipv4 packet
//because I didn't use PF_NET6
    struct iphdr * iph = ip_hdr(skb);
    PRINT("dest ip:%s",in_ntoa(iph->daddr));
    PRINT("protocol:%d",iph->protocol);
}*/
	//if(IN6_IS_ADDR_MULTICAST(destip))
	//if((destip)->s6_addr[0] == 0xff)
	//{
		//if the packet is a multicast packet
		//find the next destination header and change it
		//add a header to exist memory space more call crack
		//so encapulate a new sk_buff with the original data and new header
	//	ip6_encapsulate_pkt(skb);
	//	if(!*skb)
	//		return NF_STOLEN;//?
	//PRINT("multicast packet!");

	//}
	return NF_ACCEPT;
}


/*Initialize the hook*/
static struct nf_hook_ops nf_out_modify =
{
	.hook = ip6_multi_modify,
	.hooknum = NF_IP6_LOCAL_OUT,//Check all the forwarded packets
    .owner = THIS_MODULE,
	.pf = PF_INET6,
	.priority = NF_IP6_PRI_FIRST,
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
