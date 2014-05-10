##########################################################
#
#  init_regs
#
#	                         random	     2014-04-21
##########################################################

des_format = 'shellcode: init_regs' 

##########################################################

def init_regs_shellcode():
	shellcode = ''
	#init
	shellcode += '\x31\xc0\x31\xd2\x31\xdb\x31\xc9'			#xor eax,eax#xor edx,edx#xor ebx,ebx#xor ecx,ecx
	return shellcode

if __name__ == '__main__':

	shellcode = init_regs_shellcode()
