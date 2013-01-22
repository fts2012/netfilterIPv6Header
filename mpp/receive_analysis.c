/*
* this programe is working as plugin of netfilter 
* which analysis the specified packets
* work in mmp (measurement point)
*/

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include "common.h"
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/types.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiu Jin");
MODULE_DESCRIPTION("analysis the specified packets");

//static long int ip4addr = 0;
static int host_type = 0;//see as 
//module_param(ip4addr, long, S_IRUGO);

#define PRINT(fmt,args...) printk("debug, " fmt, ##args)

#define NETLINK_TEST 31
#define MAX_MSGSIZE 1024
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

/* netlink socket */
struct sock *nl_sk = NULL;
/* the process id of userspace process*/
int pid;

/* store the ip addreses which will be dealed */
ip_list  ipaddrs;


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
    skb = skb_get (__skb);
    if(skb->len >= NLMSG_SPACE(0))
    {
         nlh = nlmsg_hdr(skb);

         memcpy(str, NLMSG_DATA(nlh), sizeof(str));
         printk("Message received:%s\n",str) ;
        sscanf(str, "cmd=%s ip=%s interval=%d", command, ipaddr,&interval);
memcpy(recvaddr,ipaddr,sizeof(recvaddr));
//convert ipaddr to struct in6_addr

// the comand format
// ADD>x:x:x:x
// DEL>x:x:x:x
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

/*void netlink_test() {
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    int err;
    u32 pid;    

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 1,
                                 nl_data_ready, NULL, THIS_MODULE);

    sock_release(nl_sk->socket);
}*/

/*
* Hook deal with the the ipv6 packets, block specified address
*/
static unsigned int 
ip6_analysis_pkt(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*))
{
    struct sk_buff *sk = skb;
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);//header
	struct ip6_dst_hdr *ip6_dst;

    if(ip6_hdr->version == 6)
    {
        struct in6_addr destip = ip6_hdr->daddr;//destination ip
        //specify the ipv6 address that need block
        //if(destip.s6_addr[0] == 0xff && destip.s6_addr[1] == 0x15)

        if(match_rule(ipaddrs, &destip))
        {
            //if it match the condition then drop it
            if(ip6_hdr->nexthdr == 0x3c)
            {
                	ip6_dst = (struct ip6_dst_hdr *)(skb->data + 40);
                    //write this information into a process
                    PRINT("sequence number:%u ",ntohl(ip6_dst->ip6d_ssn));
                    PRINT("time:%Lu ",ntohl(ip6_dst->ip6d_sec));
                    PRINT("utime:%Lu ",ntohl(ip6_dst->ip6d_usec));
                    //drop these packets
                    return NF_ACCEPT;
            }
            else
            {
                //Measurement point has no need to play the vedio
                //return NF_DROP;
            }

        }
    }
    
    return NF_ACCEPT;
}


/*Initialize the hook*/
static struct nf_hook_ops nf_in_analysis = 
{
	.hook = ip6_analysis_pkt,
	.hooknum = NF_IP6_LOCAL_IN,//SEE IF MULTICAST PASS HERE
	.pf = PF_INET6,
	.priority = NF_IP6_PRI_FIRST,
};

/*Initialize the module*/
static int __init ip6_analysisi_init(void)
{
	int ret;
    //create netlink socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 1,
                                 nl_data_ready, NULL, THIS_MODULE);

    if(!nl_sk){
        printk(KERN_ERR "create netlink socket error.\n");
        return 1;
    }
    
    //register hooks
	ret = nf_register_hook(&nf_in_analysis);
	PRINT("IPV6 packets receive and analysis module init.\n");
	return 0; //success
}

/*Clear the module*/
static void __exit ip6_analysisi_exit(void)
{
    //release netlink socket
    if(nl_sk != NULL){
        sock_release(nl_sk->sk_socket);
    }
    //unregister
	nf_unregister_hook(&nf_in_analysis);
	PRINT("IPV6 packets receive and analysis module exit.\n");
}

module_init(ip6_analysisi_init);
module_exit(ip6_analysisi_exit);
