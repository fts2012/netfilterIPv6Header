
/**
 * Some common struts and functions used in both server and client
 * 'work on the userspace' with share memory
 * for two threads
 */

#include "common.h"
#include <stdio.h>
#include <string.h>

int size_shm;
ip_node *node_ptr = NULL;
/*
 * init the list of rules
 */
int create_shm(const char *shm_name, int size)
{
    int shm_id;
    key_t key;    
   key = ftok(shm_name,0);
    size_shm = size;
    if(key == -1)
		return 0;

    //key =0x000010231;//why use this the segment fault won't happen while ftok happens
	shm_id = shmget(key,size_shm*sizeof(ip_node)*2,IPC_CREAT|0644);
    if(shm_id == -1)
	{
		printf("shmget error");
		return 0;
	}
    
    //set 0
    node_ptr = (ip_node *)shmat(shm_id,NULL,0);
    memset(node_ptr, 0 ,size_shm*sizeof(ip_node)*2);

    return shm_id;
}


int match_rule(int shm_id, struct in6_addr * check_ip)
{
    int i;
    int rtn = 0;
    //travel shared memory to find whether it exist
    for(i = 0;i<size_shm;i++)
    {
        //is the item is in use and the address of the item is equal to the checking ip 
        if((*(node_ptr+i)).is_use && memcmp(&(*(node_ptr+i)).addr,check_ip,sizeof(struct in6_addr)) == 0)
        {
            rtn = 1;
        }
    }
    return rtn;
}

/*
 *ADD the if it match the rule
 */

void add_rule(int shm_id, struct in6_addr * check_ip)
{
    int i;
    //travel shared memory to find whether it exist

    for(i = 0;i<size_shm;i++)
    {
        //find a space that not used
        if((*(node_ptr+i)).is_use==0)
        {
            (*(node_ptr+i)).is_use =1;
            memcpy(&(*(node_ptr+i)).addr,check_ip,sizeof(struct in6_addr));
            break;
        }
    }
}

/*
 *DEL the if it match the rule
 */
void del_rule(int shm_id, struct in6_addr * check_ip)
{
    int i;
    //travel shared memory to find whether it exist
    for(i = 0;i<size_shm;i++)
    {
        //find a space that match check_ip and set the space to zero
        if((*(node_ptr+i)).is_use && memcmp(&(*(node_ptr+i)).addr,check_ip,sizeof(struct in6_addr)) == 0)
        {
            (*(node_ptr+i)).is_use = 0;
            memset(&(*(node_ptr+i)).addr, 0, sizeof(struct in6_addr));
            break;
        }
    }
}

/**
 * detach the connection
 */
void free_shm(int shm_id)
{
    if(shm_id!= -1)
    {
//detach
        if(shmdt(node_ptr)==-1)
		    printf(" detach error ");
//deep delete
shmctl(shm_id , IPC_RMID , 0 );
    }
}
/*
 * Analysis str according to delim to get command and ip address
 */
void analysis_info(char *command, char *addr_str, char *str,const char *delim)
{
    char * tmp = strsep(&str,delim);
    memcpy(command,tmp,strlen(tmp));

//FIXME:段错误
    memcpy(addr_str,str,strlen(str));
}


void print_6addr(const struct in6_addr *addr)
{
    //PRINT
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

