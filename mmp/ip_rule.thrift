/**
 * Use  Mcs  as a client to send data to Mss and Mmp
 */


//namespace cppl
//namespace python

/**
 * RecvCommand is implement in both MSS and MMP where will let the kernel to receive packets matching the rule
 */
service RecvCommand{

    bool add_measure_group(1: string str_addr,2: i32 interval);

    bool del_measure_group(1: string str_addr,2: i32 interval);

}
