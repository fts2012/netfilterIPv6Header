import sys
import sqlite3
sys.path.append('./gen-py')

from deal_message import RecvMessage
from deal_message.ttypes import *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer#TProcessPoolServer #TNonblockingServer

import socket
import signal

def setupHandlers():
    signal.signal(signal.SIGINT, handleSIGINT)
    #Optionally if you want to keep the current socket connection open and working
    #tell python to make system calls non-interruptable, which is probably what you want.
    signal.siginterrupt(signal.SIGINT, False)

def handleSIGINT(sig, frame):
     #clean up state or what ever is necessary
     sys.exit(0)

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
		#split message with ; to get every item
		items = msg.strip('\n').split(';')
		print items

handler = RecvHandler()
processor = RecvMessage.Processor(handler)

transport = TSocket.TServerSocket("localhost",9090)
pfactory = TBinaryProtocol.TBinaryProtocolFactory()
tfactory = TTransport.TBufferedTransportFactory()
server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)

#server = TServer.TProcessPoolServer(processor, transport, tfactory, pfactory)
#server.setPostForkCallback(setupHandlers)
#setupHandlers()

#server = TNonblockingServer.TNonblockingServer(processor, transport, inputProtocolFactory=pfactory)



print "Starting TNonblockingServer..."
server.serve()
print "done!"
