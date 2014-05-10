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


out = ledt.rop_search('/bin/ls','pop eax')
if out:
	print "find %d gadgets!" % len(out)
	for i in xrange(len(out)):
		print "[%d] %s\t%s" % ((i+1),out[i][0],out[i][1])

#out = ledt.rop_search_wrapper('/bin/ls','pop eax')
#line_output(out)

#out = ledt.rop_search_wrapper('/bin/ls','pop eax')
#line_output(out)

###################################################
