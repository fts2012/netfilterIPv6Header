# for test
import sys
import sqlite3
sys.path.append('./gen-py')

from deal_message import RecvMessage
from deal_message.ttypes import *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TNonblockingServer

#TServer#TProcessPoolServer #

import socket

class RecvHandler:
	'''
	implement those service in thrift to communicate with clients
	'''
	def __init__(self):
		self.log = {}

	def registe_group(self, grp):
		'''
		for the source server to registe multicast group
		'''
		#status = 1 working
		sql = "insert into comm_group values (NULL ,3,grp.name,grp.deviceIp,grp.relateIp,1) "
		print sql

	def registe_device(self, dev):
		'''
		for the device to registe information such as report the ip and port 
		'''
		print "registe_device"
		sql = "insert into comm_device values (NULL ,dev.name, dev.deviceIp, dev.type, dev.relateIp, dev.listenPort, date('now')) "
		print sql

	def send_measure_info(self, msg):
		'''
		for the measure point to report the measure result
		'''
		print msg
		#split message with ; to get every item
		items = msg.strip('\n').split(';')
		print items

handler = RecvHandler()
processor = RecvMessage.Processor(handler)

transport = TSocket.TServerSocket("localhost",6542)
pfactory = TBinaryProtocol.TBinaryProtocolFactory()
tfactory = TTransport.TBufferedTransportFactory()
#server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)

#server = TServer.TProcessPoolServer(processor, transport, tfactory, pfactory)
#server.setPostForkCallback(setupHandlers)
#setupHandlers()

server = TNonblockingServer.TNonblockingServer(processor, transport, inputProtocolFactory=pfactory)



print "Starting TNonblockingServer..."
server.serve()
print "done!"
