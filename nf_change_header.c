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


/*sequence of measeure#include <asm/byteorder.h>
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

 char *in6_ntoa(struct in6_addr *addr)
  {
          static char *buff;

         sprintf(buff, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
          return(buff);

  }

struct sk_buff *
ip6_reconstruct_ori_pkt(struct sk_buff *skb)
{
	struct ipv6hdr * ip6_hdr = ipv6_hdr(skb);
	struct ip6_dst_hdr *ip6_dst;
	struct timeval tv;//get time
int i =0;
	ip6_hdr->nexthdr = 0x60;//set next header as 60 which means next destination header.
    ip6_hdr->payload_len = htons(0x26);
PRINT("%u,%u,%u\n",skb->data,skb->data+40,skb->data+skb->len);
	//move tail to tail + sizeof(ip6_dst_hdr)
	skb_put(skb, sizeof(struct ip6_dst_hdr));
    //skb->truesize += sizeof(struct ip6_dst_hdr);
    //----------till here is right-------//

	//insert a ip6_dst_hdr between the memory
	//memcpy (new_skb->data, skb->data, 40);//assume that the ip header has 40 bytes

//PRINT("HEADER before copy, %x\n",*(long *)(skb->data + 40));

for(i = skb->data; i < skb->data + skb->len -4; i = i+4)
{
    PRINT("%x",*(long *)(i));
}
PRINT("%u,%u,%u\n",skb->data,skb->data+40,skb->data+skb->len);
    //memcpy (skb->data + 40 + sizeof (struct ip6_dst_hdr),
	//		          skb->data + 40, skb->len - 56);//for the length of skb is increased 16, so we should minus 16+40 to get the left content

    int begin = skb->data + 40;
    int end = skb->data + skb->len -16;
    for(i = end; i-begin >=16; i=i-16)
    {
    memcpy(i,i-16,16);
    }
    if(i-begin>0)
        memcpy(begin+16,begin,i-begin);


//PRINT("HEADER after copy, %x\n",*(long *)(skb->data + 40+ sizeof (struct ip6_dst_hdr)));
for(i = skb->data; i < skb->data + skb->len -4; i = i+4)
{
    PRINT("%x",*(long *)(i));
}
PRINT("\n");

    //turn the space to ip6_dst struct
	ip6_dst = (struct ip6_dst_hdr *)(skb->data + 40);
    memset(ip6_dst,0,sizeof(struct ip6_dst_hdr));//clear
	//add ipv6 destination header
	ip6_dst->ip6d_nxt = 0x17;
	ip6_dst->ip6d_len = 0x15;
	ip6_dst->ip6d_opt_type = 0x00;// type of option
	ip6_dst->ip6d_opt_len = 0x0C;

	do_gettimeofday(&tv);
	//ip6_dst->ip6d_sec =x(2.4.21-37.EL htonl(tv.tv_sec);
    ip6_dst->ip6d_sec = htonl(tv.tv_sec);
	ip6_dst->ip6d_usec = htonl(tv.tv_usec);
//PRINT("time:%x,%x \n",tv.tv_sec,tv.tv_usec);
	sample_seq++;
	if(sample_seq==0xffffffff)//if overflow ，reset
	{
	   sample_seq=0;
	}
	ip6_dst->ip6d_ssn = htonl(sample_seq);
for(i = skb->data; i < skb->data + skb->len -4; i = i+4)
{
    PRINT("%x",*(long *)(i));
}
//PRINT("HEADER new, %x\n",*(struct ip6_dst_hdr *)(skb->data + 40));
//PRINT("HEADER new 40, %x\n",*(struct ip6_dst_hdr *)(skb->data + 40+ sizeof (struct ip6_dst_hdr)));
	return skb;
}

struct sk_buff *
ip6_encapsulate_pkt(struct sk_buff *skb)
{
	struct sk_buff *new_skb, *temp_skb;
	struct ipv6hdr * ip6_hdr = ipv6_hdr(skb);
	struct ip6_dst_hdr *ip6_dst;
	struct timeval tv;//get time

	ip6_hdr->nexthdr = 0x60;//set next header as 60 which means next destination header.

	//copy from the *skb to new_skb
	new_skb = skb_copy_expand(skb, skb_headroom(skb),
				skb_tailroom(skb) + sizeof(struct ip6_dst_hdr),
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
	skb_put(new_skb,sizeof(struct ip6_dst_hdr));
    
    //----------till here is right-------//
    memcpy (skb->data + 40 + sizeof (struct ip6_dst_hdr),
			          skb->data + 40, skb->len - 56);//for the length of skb is increased 16, so we should minus 16+40 to get the left content

	//insert a ip6_dst_hdr between the memory
	memcpy (new_skb->data, skb->data, 40);//assume that the ip header has 40 bytes

    memcpy (new_skb->data + 40 + sizeof (struct ip6_dst_hdr),
			          skb->data + 40, skb->len - 40);

//now the data in 40 and 40+sizeof (struct ip6_dst_hdr) are same
//
PRINT("HEADER new, %x\n",*(new_skb->data + 42));
PRINT("HEADER new 40, %x\n",*(new_skb->data + 42+ sizeof (struct ip6_dst_hdr)));
	//release the old struct
//FOR TEST:
//	kfree_skb(skb);

	skb = new_skb;//skb pointer to new_skb

    //turn the space to ip6_dst struct
	ip6_dst = (struct ip6_dst_hdr *)(skb->data + 40);
    memset(ip6_dst,0,sizeof(struct ip6_dst_hdr));//clear
	//add ipv6 destination header
	ip6_dst->ip6d_nxt = 0x11;
	ip6_dst->ip6d_len = 0x15;
	ip6_dst->ip6d_opt_type = 0x00;// type of option
	ip6_dst->ip6d_opt_len = 0x0C;
PRINT("HEADER ip6d_nxt, %x\n",ip6_dst->ip6d_nxt);
PRINT("HEADER ipdst, %x\n",*(ip6_dst));
PRINT("HEADER new, %x\n",*(int *)(skb->data + 40));
	do_gettimeofday(&tv);
	//ip6_dst->ip6d_sec =x(2.4.21-37.EL htonl(tv.tv_sec);
    ip6_dst->ip6d_sec = htonl(tv.tv_sec);
	ip6_dst->ip6d_usec = htonl(tv.tv_usec);
//PRINT("time:%x,%x \n",tv.tv_sec,tv.tv_usec);
	sample_seq++;
	if(sample_seq==0xffffffff)//if overflow ，reset
	{
	   sample_seq=0;
	}
	ip6_dst->ip6d_ssn = htonl(sample_seq);

ip6_hdr->hop_limit = 1;
	//checksum, ipv6 dose not have a checksum part
//ip6_hdr = ipv6_hdr(new_skb);
//PRINT("new skb next hdr:%x",&ip6_hdr->nexthdr);
	return skb;
}


/*test begin*/
struct sk_buff *
ip6_encapsulate_pkt_t(struct sk_buff *skb)
{
	struct sk_buff *new_skb, *temp_skb;
	struct ipv6hdr * ipv6h;
    struct udphdr *udph;

	

	//copy from the *skb to new_skb
	new_skb = skb_copy(skb, GFP_ATOMIC);
	if(new_skb == NULL)
	{
		PRINT("Allocate new sk_buffer error!\n");
		//FIXME:if error happens ,will free the last struct cause any problem?
		kfree_skb(skb);
		return NULL;
	}
    udph = udp_hdr(skb);
	printk(" skb sum %u,CheckSum  = %u\n",skb->ip_summed,udph->check);

    __be16 udplen = udph->len;
    ipv6h = ipv6_hdr(skb);
    //udphdr = 
    ipv6h->nexthdr = 0x60;//set next header as 60 which means next destination header.
    
    //ip6_hdr->flow_lbl = 
    udph->check = csum_ipv6_magic(&ipv6h->saddr,&ipv6h->daddr, udplen,IPPROTO_UDP, csum_partial((char*)udph,udplen,0));
		printk(" skb sum %u,CheckSum  = %u\n",skb->ip_summed,udph->check);
    //kfree_skb(skb);
    skb = new_skb;//skb pointer to new_skb
    
	
//ip6_hdr = ipv6_hdr(new_skb);
//PRINT("new skb next hdr:%x",&ip6_hdr->nexthdr);
	return skb;
}
/*test end*/
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
        if(skb_tailroom(sk) >= 40)
        {
            PRINT("tailroom is enough\n");
            skb = ip6_reconstruct_ori_pkt(skb);
        }
        else
        {
            
            skb = ip6_encapsulate_pkt(skb);
            PRINT("not enough\n");
        }
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
	.hooknum = NF_IP6_PRE_ROUTING,//Check all the forwarded packets
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
