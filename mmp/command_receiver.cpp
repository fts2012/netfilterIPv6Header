/**
 * work as a server to receive the command of add or delete ip rule
 */

#include <thrift/concurrency/ThreadManager.h>
#include <thrift/concurrency/PosixThreadFactory.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/server/TThreadPoolServer.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include "common.h"
#include <arpa/inet.h>//inet_ntop
#include <libconfig.h++> //libpconfig
#include <net/if.h>//if_nametoindex(char *)
#include "./gen-cpp/RecvCommand.h"

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace boost;
using namespace libconfig;

class RecvCommandHandler: virtual public RecvCommandIf {
public:
	RecvCommandHandler() {
	}
	RecvCommandHandler(int shmid, string name) {
		shm_id = shmid;
		ifname = name;
	}

	bool add_measure_group(const std::string& addr, const int32_t interval,
			const int32_t port) {
		//socket
		int rc_fd;
		const int yes = 1;
		//address
		struct sockaddr_in6 saddr;
		struct ipv6_mreq mreq;

		struct in6_addr s; // IPv6地址结构体
		inet_pton(AF_INET6, addr.c_str(), (void *) &s);
		//join the group
		//1. 创建socket
		if ((rc_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
			std::cout << "socket error" << std::endl;
			return 0;
		}
		//2.设置socket
		if (setsockopt(rc_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))
				< 0) {
			std::cout << "Reusing ADDR failed" << std::endl;
			return 0;
		}

		//bzero(&addr, sizeof(addr)); //清空
		saddr.sin6_family = AF_INET6;
		saddr.sin6_port = htons(port);
		saddr.sin6_addr = in6addr_any; //为什么这边必须是in6addr_any?否则就阻塞
		inet_pton(AF_INET6, addr.c_str(), &saddr.sin6_addr);

		//3 bind
		if (bind(rc_fd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in6))
				< 0) {
			std::cout << "bind error" << std::endl;
			return 0;
		}
		//4.加入组播地址
		//mreq.ipv6mr_multiaddr.in6_addr=inet_addr(Receiver::jion_group);
		inet_pton(AF_INET6, addr.c_str(), &mreq.ipv6mr_multiaddr);
		//	memcpy(&mreq.ipv6mr_multiaddr, &addr.sin6_addr,
		//			sizeof(struct in6_addr));

		mreq.ipv6mr_interface = if_nametoindex("eth0");
		/* use setsockopt() to request that the kernel join a multicast group */
		if (setsockopt(rc_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq,
				sizeof(mreq)) < 0) {
			std::cout << "setsockopt" << std::endl;
			return 0;
		}

		//add to map
		sockfd_addr[addr] = rc_fd;
		//add it to the rule
		add_rule(shm_id, &s);
		return true;
	}

	bool del_measure_group(const std::string &addr, const int32_t interval,
			const int32_t port) {
		cout << "del rule" << addr << endl;
		struct in6_addr s; // IPv6地址结构体
		inet_pton(AF_INET6, addr.c_str(), (void *) &s);
		int sockfd;
		//1. stop catch the packets that match this rule
		del_rule(shm_id, &s);

		//delete from sockfd_addr
		if (sockfd_addr.count(addr)) {
			//2. get socket fd
			sockfd = sockfd_addr[addr];

			//3. leave the group
			struct ipv6_mreq mreq6;
			memcpy(&mreq6.ipv6mr_multiaddr, &s, sizeof(struct in6_addr));
			mreq6.ipv6mr_interface = if_nametoindex("eth0");

			setsockopt(sockfd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6,
					sizeof(mreq6));

			//4.close fd
			//close(fd);
			//5. erase the fd and address
			sockfd_addr.erase(addr);
		}
		return true;
	}

protected:
	map<string, int> sockfd_addr;

private:
	int shm_id; //share memory id
	string ifname;

};

int main(int argc, char **argv) {

	char file_shm[20];
	int size_of_shm;
	int port;
	Config cfg;
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile("mmp_ini.cfg");
	} catch (const FileIOException &fioex) {
		std::cerr << "I/O error while reading file." << std::endl;
		return (EXIT_FAILURE);
	} catch (const ParseException &pex) {
		std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
				<< " - " << pex.getError() << std::endl;
		return (EXIT_FAILURE);
	}
	try {
		strcpy(file_shm, cfg.lookup("file_shm").c_str());
		size_of_shm = cfg.lookup("size_of_shm");
		port = cfg.lookup("mcs_port");
		string ifname = cfg.lookup("iterface_name");

		//create share memory
		int shm_id = create_shm(file_shm, size_of_shm);
		if (shm_id == 0)
			return 0;

		//server single connect with mcs
		shared_ptr<TProtocolFactory> protocolFactory(
				new TBinaryProtocolFactory());
		shared_ptr<RecvCommandHandler> handler(
				new RecvCommandHandler(shm_id, ifname));
		shared_ptr<TProcessor> processor(new RecvCommandProcessor(handler));
		shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
		shared_ptr<TTransportFactory> transportFactory(
				new TBufferedTransportFactory());

		TSimpleServer server(processor, serverTransport, transportFactory,
				protocolFactory);

		/**
		 * Or you could do one of these

		 shared_ptr<ThreadManager> threadManager =
		 ThreadManager::newSimpleThreadManager(workerCount);
		 shared_ptr<PosixThreadFactory> threadFactory =
		 shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
		 threadManager->threadFactory(threadFactory);
		 threadManager->start();
		 TThreadPoolServer server(processor,
		 serverTransport,
		 transportFactory,
		 protocolFactory,
		 threadManager);

		 TThreadedServer server(processor,
		 serverTransport,
		 transportFactory,
		 protocolFactory);

		 */

		printf("Starting the server...\n");
		server.serve();
		free_shm(shm_id);
		printf("done.\n");
	} catch (const SettingNotFoundException &nfex) {
		cerr << "No 'name' setting in configuration file." << endl;
	}
	return 0;
}
