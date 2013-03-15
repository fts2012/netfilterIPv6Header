#ifndef COM_KERNEL_MSS_H
#define COM_KERNEL_MSS_H

#define NETLINK_TEST 30
#define MAX_PAYLOAD 1024 // maximum payload size

int send_msg_to_kernel(const char* cmd);

#endif
