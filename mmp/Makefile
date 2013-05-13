#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#
# Make file of mmp
THRIFT_VER =thrift-0.9.0
USR_DIR    =${HOME}/usr
THRIFT_DIR =${USR_DIR}/${THRIFT_VER}
INCS_DIRS  =-I${USR_DIR}/include -I${THRIFT_DIR}/include/thrift
LIBS_DIRS  =-L${USR_DIR}/lib -L${USR_DIR}/${THRIFT_VER}/lib
CPP_DEFS   =-D=HAVE_NETINET_IN_H 
CPP_OPTS   =-Wall -O2
LIBS       =-lpcap -lconfig++  -lthrift -lthriftz

GEN_SRC    = ./gen-cpp/deal_message_types.cpp \
             ./gen-cpp/RecvMessage.cpp \
           ./gen-cpp/ip_rule_constants.cpp \
           ./gen-cpp/RecvCommand.cpp
GEN_INC    = -I./gen-cpp

#default: server client
default:  client server
#server: 
#	g++ ${CPP_OPTS} ${CPP_DEFS} -o CppServer ${GEN_INC} ${INCS_DIRS} CppServer.cpp ${GEN_SRC} ${LIBS_DIRS} ${LIBS}
server:
	g++ ${CPP_OPTS} ${CPP_DEFS} -o command_receiver ${GEN_INC} ${INCS_DIRS} common.c send_measure_info.cpp command_receiver.cpp ${GEN_SRC} ${LIBS_DIRS} ${LIBS} 

client: 
	g++ ${CPP_OPTS} ${CPP_DEFS} -o catch_packets ${GEN_INC} ${INCS_DIRS} common.c send_measure_info.cpp catch_pkt.cpp ${GEN_SRC} ${LIBS_DIRS} ${LIBS}

clean:
	$(RM) -r catch_packets  command_receiver
