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

data = "ssssssssssssss"
ledt.send('127.0.0.1',4444,data)
ledt.read()
ledt.close()