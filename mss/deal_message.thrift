
//the format of message of register device
struct Device {
	1: string name,
	2: string deviceIp,
	3: i32 deviceType,
	4: string relateIp,
	5: i32 listenPort
}

//the format of message for register of multicast group
struct Group{
	1: string name,
	2: string deviceIp,
	3: string groupIp,
	4: i32 groupport
}

/**
 * wait the measure information send by mmp, or mmp and mss to registe 
 */
service RecvMessage{
	//register the multicast group
	void registe_group(1: Group grp);
	
	// registe the device
	void registe_device(1: Device dev);
	
	//wait the measure information send by mmp
	void send_measure_info(1: string msg); 
}