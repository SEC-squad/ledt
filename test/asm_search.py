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


out = ledt.asm_search('/lib/i386-linux-gnu/i686/cmov/libc-2.13.so','pop eax;ret')
if out:
	print "find %d gadgets!" % len(out)
	for i in xrange(len(out)):
		print "[%d] %s\t%s\t%s" % ((i+1),out[i][0],out[i][1],out[i][2])

#out = ledt.asm_search_wrapper('/lib/i386-linux-gnu/i686/cmov/libc-2.13.so','pop eax;ret')
#line_output(out)

#out = ledt.asm_search_wrapper('/bin/ls','pop eax')
#line_output(out)

###################################################
