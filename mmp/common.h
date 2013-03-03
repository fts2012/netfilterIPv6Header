#ifndef COMMON_H
#define COMMON_H

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <inttypes.h>
#include <arpa/inet.h>

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
typedef struct
{
    //ip_node* pre;
    short is_use;
    //the numeric express of ipv6 address
    struct in6_addr addr;
    //char  addr[INET6_ADDRSTRLEN];//if it use pointer there will point to one place,easy get wrong
} ip_node;

/*
 * create a share memory space
 */
int create_shm(const char *shm_name, int size_shm);

/*
 *To the if it match the rull
 */
int match_rule(int shm_id, struct in6_addr * check_ip);


/*
 * Add a rull
 */
void add_rule(int shm_id, struct in6_addr * check_ip);

/*
 * Delete  the rull
 */
void del_rule(int shm_id, struct in6_addr * check_ip);

/**
 * Analysis the str to get command and ip address
 */
void analysis_info(char *command, char *addr_str, char *str, const char *delim);

/*
 * print ipv6 address
 */
void print_6addr(const struct in6_addr *addr);


#endif
