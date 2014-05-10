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



val = 0x31323334

out = little16(val)
line_output(out)

out = little16str(val)
line_output(out)

out = little32(val)
line_output(out)

out = little32str(val)
line_output(out)

out = little64(val)
line_output(out)

out = little64str(val)
line_output(out)