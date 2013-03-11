#ifndef SEND_MESSAGE_INFO_H
#define SEND_MESSAGE_INFO_H

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

#include <string>
#include <iostream>

class MessageHandler{

public:
	MessageHandler(const std::string mcs_ip, int port );

	MessageHandler(const MessageHandler& mh);
	
	MessageHandler& operator=(const MessageHandler &);
	
	int sendmsg(const std::string& msg);

	void registe_group(const std::string name, const std::string deviceIp,
			std::string groupIp);

	void registe_device(const std::string name, const std::string deviceIp,
			int deviceType, const std::string relateIp, int listenPort);

private:
	std::string mcs_ip;

	int port;
};




#endif
