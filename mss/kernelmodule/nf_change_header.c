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
#include "common.h"
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

/* netlink socket */
struct sock *nl_sk = NULL;
/* the process id of userspace process*/
int pid;


/* store the ip addreses which will be dealed */
ip_list  ipaddrs = NULL;
/**
 * Send message to userspace
 */
void sendnlmsg(char *message)
{
    struct sk_buff *nskb;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;
    if(!message || !nl_sk)
    {
        return ;
    }

    //allocate space
    nskb = alloc_skb(len,GFP_KERNEL);
    if(!nskb)
    {
        printk(KERN_ERR "alloc_skb send to userspace error\n");
    }

    slen = strlen(message);
    //construct the packent
    nlh = nlmsg_put(nskb,0,0,0,MAX_MSGSIZE,0);
    NETLINK_CB(nskb).pid = 0;
    NETLINK_CB(nskb).dst_group = 0;
    memcpy(NLMSG_DATA(nlh), message, slen+1);

    //sent unicast message
    netlink_unicast(nl_sk, nskb, pid, MSG_DONTWAIT);
}


/* 
 * Accpet the commands from user space to set the rules
 */
void nl_data_ready(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char str[100];
    //struct completion cmpl;
    int i=10;
    int interval = 0;
    char command[6] ={'\0'},ipaddr[60]={'\0'};
    struct in6_addr recvaddr;
    printk("nl_data_ready......in\n");

    skb = skb_get (__skb);
    if(skb->len >= NLMSG_SPACE(0))
    {
        nlh = nlmsg_hdr(skb);

        memcpy(str, NLMSG_DATA(nlh), sizeof(str));
        printk("Message received:%s\n",str) ;
        sscanf(str, "cmd=%s ip=%s interval=%d", command, ipaddr,&interval);
        memcpy(&recvaddr,ipaddr,sizeof(recvaddr));
        //TODO 比较出问题，用ip格式和string比较
        print_6addr(&recvaddr);
//convert ipaddr to struct in6_alddr

// the comand format
// ADD>x:x:x:x
// DEL>x:x:x:x
        //
        if(strcmp(command,"ADD")==0)
         {

              add_rule(&ipaddrs, &recvaddr);
         }
         else if(strcmp(command,"DEL")==0)
         {
              del_rule(&ipaddrs, &recvaddr);
         }

         pid = nlh->nlmsg_pid; //the source process id

         sendnlmsg("command executed.");

         kfree_skb(skb);
     }
 }

/**
 * add the destination header in original packet
 */
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
	//move tail to tail + sizeof(ip6_dst_hdr)
	skb_put(skb, sizeof(struct ip6_dst_hdr));
    skb->truesize += sizeof(struct ip6_dst_hdr);


	//insert a ip6_dst_hdr between the memory

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

/**
 * copy the packet to construct a new packet and add extention header
 */
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
    if(match_rule(&ipaddrs, &destip))
    {
    	//FIXME:The size of tail room

        if(skb_tailroom(sk) >= 40)
        {
            PRINT("tailroom is enough\n");
            skb = ip6_reconstruct_ori_pkt(skb);
        }
        else
        {
            if(ip6_hdr->nexthdr == 0x11){
        
        //if(ip6_hdr->nexthdr != 0x3c){
            //if the next header is no 60 that is this packet was not reconstructed
            skb = ip6_reconstruct_copy_pkt(skb);
            ip_route_me_harder(skb,RTN_LOCAL);//ip6_route_me_harder
            okfn(skb);  
            //drop the old skb
            //TODO:WHAT WILL DROP?
            return NF_ACCEPT;
        }
        //        PRINT("not enough\n");
        //    }
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
	.hooknum = NF_IP6_LOCAL_OUT,//Check all the forwarded packets
    .owner = THIS_MODULE,
	.pf = PF_INET6,
	.priority = NF_IP6_PRI_FIRST,
};

/*Initialize the module*/
static int __init ip6_multi_init(void)
{
	int ret;
    //create netlink socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 0,
                                 nl_data_ready, NULL, THIS_MODULE);

    if(!nl_sk){
        printk(KERN_ERR "create netlink socket error.\n");
        return 0;
    }

	ret = nf_register_hook(&nf_out_modify);
	PRINT("IPV6 multicast packet modify module init.\n");
	return 0; //success
}

/*Clear the module*/
static void __exit ip6_multi_exit(void)
{
    //release netlink socket
    if(nl_sk != NULL){
        sock_release(nl_sk->sk_socket);
    }

	nf_unregister_hook(&nf_out_modify);
	PRINT("IPV6 multicast packet modify module exit.\n");
}

module_init(ip6_multi_init);
module_exit(ip6_multi_exit);
