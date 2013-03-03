#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

int main()
{
    char *file = "./shm4";
    int size = 50;
    int shm_id = create_shm(file, size);
    if(shm_id == 0)
        return 0;
    struct in6_addr s; // IPv6地址结构体
 char command[6] ={'\0'},ipaddr[60]={'\0'};
    char inputs[60];
char *cmds;
    while(1)
    {
        printf("Please input command: 'ADD/DEL + addr' or 'q' \n");
        scanf("%s", inputs);
        if(strncmp(inputs,"q",1) == 0)
           break;
        else
        {
            sscanf(inputs, "%[A-Za-z]>%s", command, ipaddr);
            cmds = inputs;
//            analysis_info(command, ipaddr, cmds, ">");

            inet_pton(AF_INET6, ipaddr, (void *)&s);
            if(strcmp(command,"ADD")==0)
            {

                add_rule(shm_id, &s);
            }
            else if(strcmp(command,"DEL")==0)
            {
                del_rule(shm_id, &s);
            }
            else if(strcmp(command, "SCH")==0)
            {
                if(match_rule(shm_id, &s))
                    printf("shot\n");
                else
                    printf("not in\n");
            }
        }
    }
    free_shm(shm_id);
}

