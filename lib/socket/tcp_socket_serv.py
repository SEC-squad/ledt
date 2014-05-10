###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################
from socket  import *
from time import ctime


BUFFER_SIZE = 1024


class TcpSocketServer(object):

	def __init__(self):
		pass

	@staticmethod
	def start(ip,port,bufsize=BUFFER_SIZE):

		if not isinstance(ip,str) :
			print "ip must be a string!"
			return False 

		if not isinstance(port,(int,long)):
			print "port must be int/long type!"
			return False 

		if not isinstance(bufsize,(int,long)):
			print "bufsize must be int/long type!"
			return False 

		ServerSock = socket(AF_INET , SOCK_STREAM)

		ServerSock.bind((ip,port))

		ServerSock.listen(10)

		print "listen on {0}:{1}".format(ip,port)

		while True:
			cs,client_addr = ServerSock.accept()
			print "connected from remote host %s:%s" % client_addr
			while True:
				data = cs.recv(bufsize)
				if not data :
					#print "error: no data recived!\n"
					break
				print "recv data:%s" % data
				cs.send("["+ctime()+"] "+data)

if __name__ == '__main__':
	TcpSocketServer.start('127.0.0.1',4444,4096)