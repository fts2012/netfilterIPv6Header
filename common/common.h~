
#include <linux/in6.h>
//#include <string.h>

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

/*The list of rules where ip address to be check
 */
typedef struct _ip_node
{
    //ip_node* pre;
    struct _ip_node* next;
    //the numeric express of ipv6 address
    //in6_addr addr;
    char  addr[INET6_ADDRSTRLEN];//if it use pointer there will point to one place,easy get wrong
} *ip_node;

typedef struct _ip_list
{
    ip_node  head;
    ip_node  tail;
    int count;
} *ip_list;


void init(ip_list *ipaddrs);
/*
 *To the if it match the rull
 */
int match_rule2(const ip_list ipaddrs, char * check_ip);
int match_rule(const ip_list ipaddrs, struct in6_addr * check_ip);


/*
 * Add a rull
 */
void add_rule(ip_list *ipaddrs, char *check_ip);

/*
 * Delete  the rull
 */
void del_rule(ip_list *ipaddrs, char *check_ip);
//bool add_rule(ip_list *ipaddrs, in6_addr check_ip)

/**
 * Analysis the str to get command and ip address
 */
void analysis_info(char *command, char *addr_str, char *str, const char *delim);

/*
 * print ipv6 address
 */
void print_6addr(const struct in6_addr *addr);
