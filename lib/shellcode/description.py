##########################################################
#
#	description shellcode fucntion
#
#	                         random	     2014-04-21
##########################################################
def description(language, des_format, out=()):
	if language=='c':
		des = '\n/*\n*  '+ des_format +'\n*/'
	elif language=='python':
		des = '\n#  '+ des_format +'  #'
	elif language=='perl':
		des = '\n#  '+ des_format +'  #'
	else:
		return 
	print des % (out)


##########################################################
des_format = 'shellcode: bind port at 127.0.0.1:%s && %s' 
out_string = (str(4444),'ssssssss')
##########################################################
if __name__ == '__main__':
	language = 'c'
	description(language,des_format,out_string)