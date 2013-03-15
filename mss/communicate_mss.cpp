// This autogenerated skeleton file illustrates how to build a server.
// You should copy it to another filename to avoid overwriting it.

/**
 * Executer is work on MSS which tell the source to execute some commands.
 * 1. accept command from mcs
 * 2. pass command to the kernel
 */

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <libconfig.h++> //libpconfig
#include  "./gen-cpp/RecvCommand.h"
#include "com_kernel_mss.h"
#include "send_measure_info.h"
#include <string>
#include<arpa/inet.h>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using namespace std;
using boost::shared_ptr;
using namespace libconfig;

class RecvCommandHandler: virtual public RecvCommandIf {
public:
	RecvCommandHandler() {
		// Your initialization goes here
	}

	bool add_measure_group(const std::string& str_addr, const int32_t interval,
			const int32_t port) {

		char buffer[72];
		sprintf(buffer, "cmd=ADD ip=%s interval=%d", str_addr.c_str(), interval);
		int rtn = send_msg_to_kernel(buffer);

		return rtn;
	}

	bool del_measure_group(const std::string& str_addr, const int32_t interval,
			const int32_t port) {
		char buffer[72];
		sprintf(buffer, "cmd=DEL ip=%s interval=%d", str_addr.c_str(), interval);

		int rtn = send_msg_to_kernel(buffer);

		return rtn;
	}

	int32_t is_alive() {

	    return 1;
	  }

};

// http://mail-archives.apache.org/mod_mbox/incubator-thrift-user/200905.mbox/%3C79457101792928636947652638746352105373-Webmail@me.com%3E
// Error"<Host: ::ffff:121.248.29.109 Port: 54804>Connection reset by peer" will occur
//2012.2.25 no solution now, but it won't affect the process

int main(int argc, char **argv) {
	Config cfg;
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile("mss_ini.cfg");
	} catch (const FileIOException &fioex) {
		std::cerr << "I/O error while reading file." << std::endl;
		return (EXIT_FAILURE);
	} catch (const ParseException &pex) {
		std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
				<< " - " << pex.getError() << std::endl;
		return (EXIT_FAILURE);
	}
	try {
		int port = cfg.lookup("mcs_port");
		string ifname = cfg.lookup("interface_name");

		// register to the mcs
		string mcs_ip = cfg.lookup("mcs_ip");
		string device_name = cfg.lookup("device_name");
		string device_ip = cfg.lookup("device_ip");
		int device_port = cfg.lookup("listen_port");
		MessageHandler mh = MessageHandler(mcs_ip, port);
		//FIXME What if error happen when regist
		mh.registe_device(device_name, device_ip, 1, "", device_port);


		shared_ptr<RecvCommandHandler> handler(new RecvCommandHandler());
		shared_ptr<TProcessor> processor(new RecvCommandProcessor(handler));
		shared_ptr<TServerTransport> serverTransport(new TServerSocket(device_port));
		shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
		shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

		TSimpleServer server(processor, serverTransport, transportFactory,
				protocolFactory);
		//TODO TEST
		struct in6_addr s; // IPv6地址结构体
		inet_pton(AF_INET6, "ff15::1", (void *) &s);
		char dst[60];
		inet_ntop(AF_INET6, (void *) &s, dst, sizeof(s));
		//
		char  msg[100];
sprintf(msg, "cmd=ADD ip=%s interval=10", dst);
		//send_msg_to_kernel("cmd=ADD ip=ff15::1 interval=10");
		send_msg_to_kernel(msg);

		printf("Starting the mss server...\n");
		server.serve();
		printf("done.\n");
	} catch (const SettingNotFoundException &nfex) {
		cerr << "No 'name' setting in configuration file." << endl;
	}
	return 0;
}

