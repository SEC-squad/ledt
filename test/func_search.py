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


###################################################################################################
#  
#  funcsearch(binfile, funcname, section_name = 'EXEC',exactly = False)
#
#  Search fucntion in all executable sections (.text/.plt/.init/.fini/..)
#
#  if section_name = 'EXEC' , it will search all executable sections
#     normally includeing .text / .init / .fini /.plt 
#
###################################################################################################

out = ledt.funcsearch('/root/Desktop/libc.so', 'exit')
line_output(out)

#out = ledt.funcsearch('/root/Desktop/libc.so', 'exit','EXEC')
#line_output(out)

#out = ledt.funcsearch('/root/Desktop/libc.so', 'exit','.text')
#line_output(out)


#out = ledt.funcsearch('/root/Desktop/libc.so', 'exit','EXEC',False)
#line_output(out)

#out = ledt.funcsearch('/root/Desktop/libc.so', 'exit','EXEC',True)
#line_output(out)

#out = ledt.funcsearch('/root/Desktop/libc.so', 'exit','.text',False)
#line_output(out)

#out = ledt.funcsearch('/root/Desktop/libc.so', 'exit','.text',True)
#line_output(out)



###################################################################################################
#  
#  funcsearch_wrapper(binfile, funcname, section_name = 'EXEC',exactly = False,section_info=[])
#
#	setction info's format is (name,VritualAddr,Offset,Size,flags)
#
#
###################################################################################################




#out = ledt.funcsearch_wrapper('/root/Desktop/libc.so', 'exit')
#line_output(out)

#out = ledt.funcsearch_wrapper('/root/Desktop/libc.so', 'exit','EXEC')
#line_output(out)

#out = ledt.funcsearch_wrapper('/root/Desktop/libc.so', 'exit','.text')
#line_output(out)

#out = ledt.funcsearch_wrapper('/root/Desktop/libc.so', 'exit','EXEC',True)
#line_output(out)

#out = ledt.funcsearch_wrapper('/root/Desktop/libc.so', 'exit','EXEC',False)
#line_output(out)

#out = ledt.funcsearch_wrapper('/root/Desktop/libc.so', 'exit','.text',False)
#line_output(out)