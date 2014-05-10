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

out = ledt.libfunc_offset('/root/Desktop/libc.so', 'exit')
line_output(out)


out = ledt.libfunc_offset('/root/Desktop/libc.so', 'system')
line_output(out)
