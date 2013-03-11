/**
 * Autogenerated by Thrift Compiler (0.9.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef RecvMessage_H
#define RecvMessage_H

#include <thrift/TDispatchProcessor.h>
#include "deal_message_types.h"



class RecvMessageIf {
 public:
  virtual ~RecvMessageIf() {}
  virtual void registe_group(const Group& grp) = 0;
  virtual void registe_device(const Device& dev) = 0;
  virtual void send_measure_info(const std::string& msg) = 0;
};

class RecvMessageIfFactory {
 public:
  typedef RecvMessageIf Handler;

  virtual ~RecvMessageIfFactory() {}

  virtual RecvMessageIf* getHandler(const ::apache::thrift::TConnectionInfo& connInfo) = 0;
  virtual void releaseHandler(RecvMessageIf* /* handler */) = 0;
};

class RecvMessageIfSingletonFactory : virtual public RecvMessageIfFactory {
 public:
  RecvMessageIfSingletonFactory(const boost::shared_ptr<RecvMessageIf>& iface) : iface_(iface) {}
  virtual ~RecvMessageIfSingletonFactory() {}

  virtual RecvMessageIf* getHandler(const ::apache::thrift::TConnectionInfo&) {
    return iface_.get();
  }
  virtual void releaseHandler(RecvMessageIf* /* handler */) {}

 protected:
  boost::shared_ptr<RecvMessageIf> iface_;
};

class RecvMessageNull : virtual public RecvMessageIf {
 public:
  virtual ~RecvMessageNull() {}
  void registe_group(const Group& /* grp */) {
    return;
  }
  void registe_device(const Device& /* dev */) {
    return;
  }
  void send_measure_info(const std::string& /* msg */) {
    return;
  }
};

typedef struct _RecvMessage_registe_group_args__isset {
  _RecvMessage_registe_group_args__isset() : grp(false) {}
  bool grp;
} _RecvMessage_registe_group_args__isset;

class RecvMessage_registe_group_args {
 public:

  RecvMessage_registe_group_args() {
  }

  virtual ~RecvMessage_registe_group_args() throw() {}

  Group grp;

  _RecvMessage_registe_group_args__isset __isset;

  void __set_grp(const Group& val) {
    grp = val;
  }

  bool operator == (const RecvMessage_registe_group_args & rhs) const
  {
    if (!(grp == rhs.grp))
      return false;
    return true;
  }
  bool operator != (const RecvMessage_registe_group_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const RecvMessage_registe_group_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_registe_group_pargs {
 public:


  virtual ~RecvMessage_registe_group_pargs() throw() {}

  const Group* grp;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_registe_group_result {
 public:

  RecvMessage_registe_group_result() {
  }

  virtual ~RecvMessage_registe_group_result() throw() {}


  bool operator == (const RecvMessage_registe_group_result & /* rhs */) const
  {
    return true;
  }
  bool operator != (const RecvMessage_registe_group_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const RecvMessage_registe_group_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_registe_group_presult {
 public:


  virtual ~RecvMessage_registe_group_presult() throw() {}


  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

typedef struct _RecvMessage_registe_device_args__isset {
  _RecvMessage_registe_device_args__isset() : dev(false) {}
  bool dev;
} _RecvMessage_registe_device_args__isset;

class RecvMessage_registe_device_args {
 public:

  RecvMessage_registe_device_args() {
  }

  virtual ~RecvMessage_registe_device_args() throw() {}

  Device dev;

  _RecvMessage_registe_device_args__isset __isset;

  void __set_dev(const Device& val) {
    dev = val;
  }

  bool operator == (const RecvMessage_registe_device_args & rhs) const
  {
    if (!(dev == rhs.dev))
      return false;
    return true;
  }
  bool operator != (const RecvMessage_registe_device_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const RecvMessage_registe_device_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_registe_device_pargs {
 public:


  virtual ~RecvMessage_registe_device_pargs() throw() {}

  const Device* dev;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_registe_device_result {
 public:

  RecvMessage_registe_device_result() {
  }

  virtual ~RecvMessage_registe_device_result() throw() {}


  bool operator == (const RecvMessage_registe_device_result & /* rhs */) const
  {
    return true;
  }
  bool operator != (const RecvMessage_registe_device_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const RecvMessage_registe_device_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_registe_device_presult {
 public:


  virtual ~RecvMessage_registe_device_presult() throw() {}


  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

typedef struct _RecvMessage_send_measure_info_args__isset {
  _RecvMessage_send_measure_info_args__isset() : msg(false) {}
  bool msg;
} _RecvMessage_send_measure_info_args__isset;

class RecvMessage_send_measure_info_args {
 public:

  RecvMessage_send_measure_info_args() : msg() {
  }

  virtual ~RecvMessage_send_measure_info_args() throw() {}

  std::string msg;

  _RecvMessage_send_measure_info_args__isset __isset;

  void __set_msg(const std::string& val) {
    msg = val;
  }

  bool operator == (const RecvMessage_send_measure_info_args & rhs) const
  {
    if (!(msg == rhs.msg))
      return false;
    return true;
  }
  bool operator != (const RecvMessage_send_measure_info_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const RecvMessage_send_measure_info_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_send_measure_info_pargs {
 public:


  virtual ~RecvMessage_send_measure_info_pargs() throw() {}

  const std::string* msg;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_send_measure_info_result {
 public:

  RecvMessage_send_measure_info_result() {
  }

  virtual ~RecvMessage_send_measure_info_result() throw() {}


  bool operator == (const RecvMessage_send_measure_info_result & /* rhs */) const
  {
    return true;
  }
  bool operator != (const RecvMessage_send_measure_info_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const RecvMessage_send_measure_info_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class RecvMessage_send_measure_info_presult {
 public:


  virtual ~RecvMessage_send_measure_info_presult() throw() {}


  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

class RecvMessageClient : virtual public RecvMessageIf {
 public:
  RecvMessageClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) :
    piprot_(prot),
    poprot_(prot) {
    iprot_ = prot.get();
    oprot_ = prot.get();
  }
  RecvMessageClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, boost::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) :
    piprot_(iprot),
    poprot_(oprot) {
    iprot_ = iprot.get();
    oprot_ = oprot.get();
  }
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getInputProtocol() {
    return piprot_;
  }
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getOutputProtocol() {
    return poprot_;
  }
  void registe_group(const Group& grp);
  void send_registe_group(const Group& grp);
  void recv_registe_group();
  void registe_device(const Device& dev);
  void send_registe_device(const Device& dev);
  void recv_registe_device();
  void send_measure_info(const std::string& msg);
  void send_send_measure_info(const std::string& msg);
  void recv_send_measure_info();
 protected:
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> piprot_;
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> poprot_;
  ::apache::thrift::protocol::TProtocol* iprot_;
  ::apache::thrift::protocol::TProtocol* oprot_;
};

class RecvMessageProcessor : public ::apache::thrift::TDispatchProcessor {
 protected:
  boost::shared_ptr<RecvMessageIf> iface_;
  virtual bool dispatchCall(::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, const std::string& fname, int32_t seqid, void* callContext);
 private:
  typedef  void (RecvMessageProcessor::*ProcessFunction)(int32_t, ::apache::thrift::protocol::TProtocol*, ::apache::thrift::protocol::TProtocol*, void*);
  typedef std::map<std::string, ProcessFunction> ProcessMap;
  ProcessMap processMap_;
  void process_registe_group(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
  void process_registe_device(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
  void process_send_measure_info(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
 public:
  RecvMessageProcessor(boost::shared_ptr<RecvMessageIf> iface) :
    iface_(iface) {
    processMap_["registe_group"] = &RecvMessageProcessor::process_registe_group;
    processMap_["registe_device"] = &RecvMessageProcessor::process_registe_device;
    processMap_["send_measure_info"] = &RecvMessageProcessor::process_send_measure_info;
  }

  virtual ~RecvMessageProcessor() {}
};

class RecvMessageProcessorFactory : public ::apache::thrift::TProcessorFactory {
 public:
  RecvMessageProcessorFactory(const ::boost::shared_ptr< RecvMessageIfFactory >& handlerFactory) :
      handlerFactory_(handlerFactory) {}

  ::boost::shared_ptr< ::apache::thrift::TProcessor > getProcessor(const ::apache::thrift::TConnectionInfo& connInfo);

 protected:
  ::boost::shared_ptr< RecvMessageIfFactory > handlerFactory_;
};

class RecvMessageMultiface : virtual public RecvMessageIf {
 public:
  RecvMessageMultiface(std::vector<boost::shared_ptr<RecvMessageIf> >& ifaces) : ifaces_(ifaces) {
  }
  virtual ~RecvMessageMultiface() {}
 protected:
  std::vector<boost::shared_ptr<RecvMessageIf> > ifaces_;
  RecvMessageMultiface() {}
  void add(boost::shared_ptr<RecvMessageIf> iface) {
    ifaces_.push_back(iface);
  }
 public:
  void registe_group(const Group& grp) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->registe_group(grp);
    }
    ifaces_[i]->registe_group(grp);
  }

  void registe_device(const Device& dev) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->registe_device(dev);
    }
    ifaces_[i]->registe_device(dev);
  }

  void send_measure_info(const std::string& msg) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->send_measure_info(msg);
    }
    ifaces_[i]->send_measure_info(msg);
  }

};



#endif
