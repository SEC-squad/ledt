###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################

import tempfile
import sys
import struct
import string
import re
import os
import itertools
from subprocess import *
import config



def L16(val): 
	return isinstance(val, (int, long)) and struct.pack('<H',(val&0XFFFF))
def B16(val): 
	return isinstance(val, (int, long)) and struct.pack('>H',(val&0XFFFF))
def L32(val): 
	return isinstance(val, (int, long)) and struct.pack('<I',(val&0XFFFFFFFF))
def B32(val): 
	return isinstance(val, (int, long)) and struct.pack('>I',(val&0XFFFFFFFF))
def L64(val): 
	return isinstance(val, (int, long)) and struct.pack('<Q',(val&0XFFFFFFFFFFFFFFFF))
def B64(val): 
	return isinstance(val, (int, long)) and struct.pack('>Q',(val&0XFFFFFFFFFFFFFFFF))

def L16hexstr(val):
	return to_hexstr(L16(val))
def L32hexstr(val):
	return to_hexstr(L32(val))
def L64hexstr(val):
	return to_hexstr(L64(val))
def B16hexstr(val):
	return to_hexstr(B16(val))
def B32hexstr(val):
	return to_hexstr(L32(val))
def B64hexstr(val):
	return to_hexstr(B64(val))



def to_hexstr(str):
	"""
	Convert a string to hex escape represent
	"""
	return "".join(["\\x%02x" % ord(i) for i in str])

def to_hex(num):
	"""
	Convert a number to hex format
	"""
	if num < 0:
		return "-0x%x" % (-num)
	else:
		return "0x%x" % num

def to_address(num):
	"""
	Convert a number to address format in hex
	"""
	if num < 0:
		return to_hex(num)
	if num > 0xffffffff: # 64 bit
		return "0x%016x" % num
	else:
		return "0x%08x" % num

def to_int(val):
	"""
	Convert a string to int number
	"""
	try:
		return int(str(val), 0)
	except:
		return None

def str2hex(str):
	"""
	Convert a string to hex encoded format
	"""
	result = str.encode('hex')
	return result

def hex2str(hexnum):
	"""
	Convert a number in hex format to string
	"""
	if not isinstance(hexnum, str):
		hexnum = to_hex(hexnum)
	s = hexnum[2:]
	if len(s) % 2 != 0:
		s = "0" + s
	result = s.decode('hex')[::-1]
	return result

def int2hexstr(num, intsize=4):
	"""
	Convert a number to hexified string
	"""
	if intsize == 8:
		if num < 0:
			result = struct.pack("<q", num)
		else:
			result = struct.pack("<Q", num)
	else:
		if num < 0:
			result = struct.pack("<l", num)
		else:
			result = struct.pack("<L", num)
	return result



def line_output(text):
	frame = ''
	try:
		raise Exception
	except:
		frame = sys.exc_info()[2].tb_frame.f_back
		#(f.f_code.co_name, f.f_lineno)
		print("line[%d]\n%s\n"%(frame.f_lineno,text))


def check_file_exist(filepath):
	if not os.path.exists(filepath):
		print "error: file not found [%s]\n" % filepath
		return False
	return True


def escapeRegExprStr(pattern):
	"""escape reg pattern string"""
	escapepattern = ''
	escapeList = r'()[].?+{}|^$*\\'
	for i in xrange(len(pattern)):
		p = pattern[i]
		if  p in escapeList:
			p = '\\'+ p
		escapepattern += p
	return escapepattern



def tmpfile(pref="sigma-random_"):
	"""Create and return a temporary file with custom prefix"""
	return tempfile.NamedTemporaryFile(prefix=pref)


def page_output(text, pagesize=40, steps = 1):
	"""
	Paging output
	"""
	i = 0
	text = text.splitlines()
	l = len(text) / steps

	for line in text:
		print(line)
		if (i+1) % pagesize == 0:
			ans = raw_input("--More--(%d/%d)" % (i/steps+1, l))
			if ans.lower().strip() == "q":
				break
		i += 1
	return


def execute_local(cmd=[]):
	#cmd = ['/bin/ls','-l]
	if isinstance(cmd,list) and len(cmd) > 1:
		os.execv(cmd[0],cmd )
	

def execute_command(command, cmd_input=None):
	"""
	Execute external command and capture its output

	Args:
		- command (String)

	Returns:
		- output of command (String)
	"""
	result = ""
	P = Popen([command], stdout=PIPE, stdin=PIPE, shell=True)
	(result, err) = P.communicate(cmd_input)
	if err:
		print(err)
	return result




