import sys

##########################################################
#
#	format output 
#
#	                         random	     2014-04-21
##########################################################

ALIGN = 16

##########################################################


def hexify(_str):
	return '\\x%02x' % (ord(_str))

def to_hexstr(str):
	"""
	Convert a string to hex escape represent
	"""
	return "".join(["\\x%02x" % ord(i) for i in str])


def out_format(language, ouput):
	
	if language == 'bin':
			sys.stdout.write(ouput)

	if language == 'c':
			sys.stdout.write("\nchar shellcode[] = \\\n\"")
			for i in xrange(len(ouput)):
				sys.stdout.write(hexify(ouput[i]))
				if  not (i+1) % ALIGN :
					sys.stdout.write("\"\n\"")
			sys.stdout.write("\";\n\n\n")

	if language == 'python':
			sys.stdout.write("\nshellcode = \\\n\"")
			for i in xrange(len(ouput)):
				sys.stdout.write(hexify(ouput[i]))
				if  not (i+1) % ALIGN :
					sys.stdout.write("\" +\\\n\"")
			sys.stdout.write("\"\n\n\n")

	if language == 'perl':
			sys.stdout.write("\n$shellcode = \\\n\"")
			for i in xrange(len(ouput)):
				sys.stdout.write(hexify(ouput[i]))
				if  not (i+1) % ALIGN :
					sys.stdout.write("\" .\\\n\"")
			sys.stdout.write("\"\n\n\n")
	
	if language == 'php':
			sys.stdout.write("\n$shellcode = \\\n\"")
			for i in xrange(len(ouput)):
				sys.stdout.write(hexify(ouput[i]))
				if  not (i+1) % ALIGN :
					sys.stdout.write("\" .\\\n\"")
			sys.stdout.write("\"\n\n\n")	



