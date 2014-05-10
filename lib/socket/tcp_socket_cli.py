###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################
from socket  import *
from time import ctime
from time import sleep
import re

BUFFER_SIZE = 1024

class TcpSocketCli(object):

	ClientSock = ''
	data = ''
	def __init__(self):
		pass

	def send(self,ip,port,buf,bufsize=BUFFER_SIZE):

		if not isinstance(ip,str) :
			print "ip must be a string!"
			return False 

		if not isinstance(port,(int,long)):
			print "port must be int/long type!"
			return False

		if len(buf)==0:
			print "no data to send!"
			return False 

		if not isinstance(bufsize,(int,long)):
			print "bufsize must be int/long type!"
			return False 

		self.ClientSock = socket(AF_INET , SOCK_STREAM)
		self.ClientSock.connect((ip,port))
		#print "connect to server {0}:{1}".format(ip,port)
		self.ClientSock.send(buf)
		return True

		


	def loop_send(self,ip,port,buf,bufsize=BUFFER_SIZE):
		pass


	def test_read(self,bufsize=BUFFER_SIZE):

		if not self.ClientSock:
			return False
		self.data = self.ClientSock.recv(bufsize)
		if self.data:
			print "recv data: %s" % self.data
		return True

	def read(self,bufsize=BUFFER_SIZE):

		if not self.ClientSock:
			return ''
		self.data = self.ClientSock.recv(bufsize)
		if self.data:
			print  self.data
			return self.data

	def read_until(self,pattern='>',bufsize=BUFFER_SIZE):


		if not self.ClientSock:
			return False

		self.data = ''
		buf = ''
		while True:
			buf += self.ClientSock.recv(bufsize)
			if len(buf) == 0:
				break
			self.data += buf
			if pattern in buf:
				break
		return self.data
	

	def close(self):

		if not self.ClientSock:
			return False
		self.ClientSock.close()
		return True


if __name__ == '__main__':
	client = TcpSocketCli()
	client.send('127.0.0.1',4444,"sssssssssssdddsssss")
	client.read()
