// This autogenerated skeleton file illustrates how to build a server.
// You should copy it to another filename to avoid overwriting it.

#include "RecvCommand.h"
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using boost::shared_ptr;

using namespace  ;

class RecvCommandHandler : virtual public RecvCommandIf {
 public:
  RecvCommandHandler() {
    // Your initialization goes here
  }

  bool add_measure_group(const std::string& str_addr, const int32_t interval, const int32_t port) {
    // Your implementation goes here
    printf("add_measure_group\n");
  }

  bool del_measure_group(const std::string& str_addr, const int32_t interval, const int32_t port) {
    // Your implementation goes here
    printf("del_measure_group\n");
  }

};

int main(int argc, char **argv) {
  int port = 9090;
  shared_ptr<RecvCommandHandler> handler(new RecvCommandHandler());
  shared_ptr<TProcessor> processor(new RecvCommandProcessor(handler));
  shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
  shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
  shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

  TSimpleServer server(processor, serverTransport, transportFactory, protocolFactory);
  server.serve();
  return 0;
}

