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
'''
out = ledt.check_sec('/root/Desktop/libc.so')
line_output(out)

out = ledt.check_sec('/bin/ls')
line_output(out)
'''

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: python %s binfile' % (sys.argv[0]))
        exit(0)
    sys.stdout.write(ledt.check_sec(sys.argv[1]))
    

