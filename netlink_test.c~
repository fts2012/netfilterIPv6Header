#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 

#define NETLINK_TEST 31
#define MAX_MSGSIZE 1024

int stringlength(char *s);
void sendnlmsg(char * message);

int pid;
int err;

struct sock *nl_sk = NULL;//socket
int flag = 0;

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
        printk(KERN_ERR "alloc_skb error\n");
    }

    slen = stringlength(message);
    //construct the packent
    nlh = nlmsg_put(nskb,0,0,0,MAX_MSGSIZE,0);

    NETLINK_CB(nskb).pid = 0;
    NETLINK_CB(nskb).dst_group = 0;

    //message[slen-1]= '\0';//this will call an exception

    //
    memcpy(NLMSG_DATA(nlh),message,slen+1);
    printk("my_net_link:send message '%s'.\n",(char *)NLMSG_DATA(nlh));

    //sent unicast message
    netlink_unicast(nl_sk, nskb, pid, MSG_DONTWAIT);
}

int stringlength(char *s)
{
    int slen = 0;
    for(; *s; s++){
        slen++;
    }
    return slen;
}

void nl_data_ready(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char str[100];
    //struct completion cmpl;
    int i=10;
    skb = skb_get (__skb);
    if(skb->len >= NLMSG_SPACE(0))
    {
         nlh = nlmsg_hdr(skb);

         memcpy(str, NLMSG_DATA(nlh), sizeof(str));
         printk("Message received:%s\n",str) ;
         pid = nlh->nlmsg_pid; //the source process id
         while(i--)
         {
           //no need to use synchronized mechannism
           // init_completion(&cmpl);//?
           // wait_for_completion_timeout(&cmpl,3 * HZ);//?
            sendnlmsg("I am from kernel!");

         }
         flag = 1;
         kfree_skb(skb);
     }
 }

// Initialize netlink

int netlink_init(void)
{
    //create netlink socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 1,
                                 nl_data_ready, NULL, THIS_MODULE);

    if(!nl_sk){
        printk(KERN_ERR "my_net_link: create netlink socket error.\n");
        return 1;
    }
    printk("my_net_link_3: create netlink socket ok.\n");
    return 0;
}

static void netlink_exit(void)
{
    if(nl_sk != NULL){
        sock_release(nl_sk->sk_socket);
    }

    printk("my_net_link: self module exited\n");
}

module_init(netlink_init);
module_exit(netlink_exit);

MODULE_AUTHOR("frankzfz");
MODULE_LICENSE("GPL");

