/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <thrift/transport/TZlibTransport.h>
#include <thrift/transport/TBufferTransports.h>
#include "send_measure_info.h"

#include "./gen-cpp/RecvMessage.h"

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;


using namespace boost;


	/**
	 * constructor
	 */
	MessageHandler::MessageHandler(const std::string mcs_ip, int port ){
		this->mcs_ip = mcs_ip;
		this->port = port;
	}

	/**
	 * copy constructor
	 */
	MessageHandler::MessageHandler(const MessageHandler& mh ){
		this->mcs_ip = mh.mcs_ip;
		this->port = mh.port;
	}
	
	MessageHandler& 
	MessageHandler::operator=(const MessageHandler& mh ){
		this->mcs_ip = mh.mcs_ip;
		this->port = mh.port;
		return *this;
	}
	
	int MessageHandler::sendmsg(const std::string& msg) {


	  shared_ptr<TTransport> socket(new TSocket(this->mcs_ip,this->port));
//	  shared_ptr<TTransport> transport(new TFramedTransport(socket));
//	  shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

	  shared_ptr<TZlibTransport> zlibTransport(new TZlibTransport(socket));
	  shared_ptr<TTransport> transport(new TBufferedTransport(zlibTransport));
	  shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

	  RecvMessageClient client(protocol);

	  try {
		transport->open();

		cout<<"send msg:"<<msg<<endl;
		client.send_measure_info(msg);

		transport->close();
	  } catch (TException &tx) {
		printf("ERROR: %s\n", tx.what());
	  }
		return 0;
	}

	void  MessageHandler::registe_group(const std::string name, const std::string deviceIp,
				std::string groupIp, int groupport){
				Group g;
				g.name = name;
				g.deviceIp = deviceIp;
				g.groupIp = groupIp;
				g.groupport = groupport;

				  shared_ptr<TTransport> socket(new TSocket(this->mcs_ip,this->port));
				  shared_ptr<TTransport> transport(new TFramedTransport(socket));
				  shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
				  RecvMessageClient client(protocol);

				  try {
					transport->open();
					client.registe_group(g);
					transport->close();
				  } catch (TException &tx) {
					printf("ERROR: %s\n", tx.what());
				  }

		}
	void MessageHandler::registe_device(const std::string name, const std::string deviceIp,
			int deviceType, const std::string relateIp, int listenPort){
			Device d;
			d.name = name;
			d.deviceIp = deviceIp;
			d.deviceType = deviceType;
			d.relateIp = relateIp;
			d.listenPort = listenPort;

			  shared_ptr<TTransport> socket(new TSocket(this->mcs_ip,this->port));
						  shared_ptr<TTransport> transport(new TFramedTransport(socket));
						  shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
						  RecvMessageClient client(protocol);

						  try {
							transport->open();
							client.registe_device(d);
							transport->close();
						  } catch (TException &tx) {
							printf("ERROR: %s\n", tx.what());
						  }

	}


