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


out = ledt.str_search('/lib/i386-linux-gnu/i686/cmov/libc-2.13.so','/bin/sh')

if out:
	print "find %d strings!" % len(out)
	for i in xrange(len(out)):
		print "[%d] 0x%08x\t\t%s\t\t%s" % ((i+1),out[i][0],out[i][1],out[i][2])

###################################################
