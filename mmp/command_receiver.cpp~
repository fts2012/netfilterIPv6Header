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

#include "./gen-cpp/RecvCommand.h"

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace boost;

class RecvCommandHandler : public RecvCommandIf {
 public:
  RecvCommandHandler() {}

  bool add_measure_group(const std::string addr, const int32_t interval) {
    cout<<"add rule"<<addr<<endl;
    return true;
  }
  
  bool del_measure_group(const std::string addr, const int32_t interval) {
    cout<<"del rule"<<addr<<endl;
    return true;
  }


protected:
  map<int32_t, SharedStruct> log;

};

int main(int argc, char **argv) {

  shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
  shared_ptr<RecvCommandHandler> handler(new RecvCommandHandler());
  shared_ptr<TProcessor> processor(new RecvCommandProcessor(handler));
  shared_ptr<TServerTransport> serverTransport(new TServerSocket(9090));
  shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());

  TSimpleServer server(processor,
                       serverTransport,
                       transportFactory,
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
  printf("done.\n");
  return 0;
}
