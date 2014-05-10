###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################
try:
	import sys 
	sys.path.append("..") 
	from lib.ledt import *
	from lib.utils import *
except Exception,e:
	print e

ledt = LEDT()

###################################################

if __name__ == '__main__':

	rasmpath = os.getcwd()+r'/../tools/bin/radare/rasm2/rasm2'
	print ledt.rasm_disassemble(rasmpath,"nop;jmp esp")
	print ledt.rasm_disassemble(rasmpath,"and eax,0x11223344")