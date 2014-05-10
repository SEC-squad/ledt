###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################


'''
	interactive shell for ledt all commands

'''

import	os
import	sys
import	struct
import	string
from	config	import *
from	utils 	import *
#from	ledt 	import *


def interact_shell(ledt):
	'''
	spawn an interactive shell

	'''
	print config.BANNER
	print ledt.__doc__
	while True:
		try:
			action = raw_input(config.Option.get("title") % 'nasm')
			action = action.strip().split(' ')[0]
		
			if action in ['q','quit','exit','end']:
				break

			elif action in ['?','h','help']:
				print ledt.__doc__

			elif action == 'assemble':
				assemble_shell(ledt)

			elif action == 'disas':
				disassemble_shell(ledt)
			
			elif action == 'asmsearch':
				asmsearch_shell(ledt)

			elif action == 'ropsearch':
				ropsearch_shell(ledt)

			elif action == 'funcsearch':
				funcsearch_shell(ledt)

			elif action == 'shellcode':
				print "coming soon !!"	

			elif action == 'pattern':
				print "coming soon !!"	

			elif action in ['banner','reset']:
				execute_command('reset')
				print config.BANNER	

			else:
				print "bad command!\n"	
				continue

		except KeyboardInterrupt,e:
			print '\ntype \"quit\" to exit\n'
			continue

	return True



def assemble_shell(ledt):
	"""
	Assemble binary using NASM
	[mode] 
		mode: 16 / 32 / 64
	"""
	Usage = "Usage: type asmcode directly,seperated by ;\ne.g  : push eax;call eax\n"
	inst_list = []
	inst_code = ''

	mode = config.Option.get('mode')		#mode: 16 / 32 / 64
	if mode not in [16, 32, 64]:
		print('error mode')
		exit(0)

	print Usage
	inst_code = ''
	while True:
		try:
			input = raw_input(config.Option.get("title") % 'assemble')
			if input in ['back','exit','quit','q']:
				break
			if input in ['?','help']:
				print Usage
				continue
			if input == "":
				continue
			bincode = ledt.assemble(input)
			size = len(bincode)
			if size == 0:
				continue
			inst_list.append((size, bincode, input))

			inst_code += bincode
			print("opcode: \"%s\"\n" % to_hexstr(bincode))
			continue

		except KeyboardInterrupt,e:
			print '\ntype \"back\" to top level\n'
			continue

	if len(inst_code):
		print("\n\n###########################################")
		print("[opcode]\n\n\"%s\"\n" % to_hexstr(inst_code))
		asmcode = ledt.disassemble_wrapper(inst_code)
		text = ledt.shellcode_format(asmcode)
		print("[shellcode]\n\n%s" % text)
		print("###########################################\n\n")

	return True


def disassemble_shell(ledt):
	"""
	Disssemble opcode using NDISASM

	"""
	
	Usage = "Usage: type opcode directly\ne.g  : \\xff\\xe4\ntype \"back\" to top level\n"
	mode = config.Option.get('mode')		#mode: 16 / 32 / 64
	if mode not in [16, 32, 64]:
		print('error mode')
		exit(0)
	opcode_list = []

	if mode not in [16, 32, 64]:
		print('error mode')
		exit(0)

	print Usage

	while True:
		try:
			input = raw_input(config.Option.get("title") % 'disas')
			if input in ['back','exit','quit','q']:
				break
			if input in ['?','help']:
				print Usage
				continue
			if input == "":
				continue
			if len(input):
				opcode_list = (input.strip().split('\\x')[1:])
			opcode = ''
			try:
				for i  in opcode_list:
					opcode += struct.pack('B',int(i,16))
			except:	
				print "bad opcode!!"
				continue		
			size = len(opcode)
			if size == 0:
				continue
			asmcode = ledt.disassemble_wrapper(opcode)
			print asmcode

		except KeyboardInterrupt,e:
			print '\ntype \"back\" to top level\n'
			continue



def ropsearch_shell(ledt):

	offset_scope = {}

	Usage = 'Usage: ropsearch binfile \"asmcode\" [section]\n'
	print Usage

	while True:
		try:
			input = raw_input(config.Option.get("title") % 'ropsearch')
			search = " ".join((input).strip().split()).split(' ')
			if search[0] in ['back','exit','quit','q']:
				break
			elif search[0] in ['?','help']:
				print Usage
				continue	
			elif search[0]== 'ropsearch':
				p = re.compile("(ropsearch)\s*(.+)\s*(\".+\")\s*")
        			matches = p.findall(input)
				if matches:
					search = matches[0]
					if len(search) != 3:
						print Usage
						continue
					binfile = search[1].strip()
					asmcode = search[2].strip()
					if not check_file_exist(binfile): continue
					if not ledt.rop_search_wrapper(binfile,asmcode,'EXEC'): continue	#search all executable sections
			else:
				print Usage
				continue

		except KeyboardInterrupt,e:
			print '\ntype \"back\" to top level\n'
			continue



def asmsearch_shell(ledt):
	offset_scope = {}
	Usage = 'Usage:  ropsearch \"pop eax\" /bin/ls\n'
	print Usage

	while True:
		try:
			input = raw_input(config.Option.get("title") % 'asmsearch')
			search = " ".join((input).strip().split()).split(' ')
			if search[0] in ['back','exit','quit','q']:
				break
			elif search[0] in ['?','help']:
				print Usage
				continue	
			elif search[0]== 'asmsearch':
				p = re.compile("(asmsearch)\s*(\".+\")\s*(.+)\s*")
        			matches = p.findall(input)
				if matches:
					search = matches[0]
					if len(search) != 3:
						print Usage
						continue
 					asmcode = search[1].strip()
					binfile = search[2].strip()
					if not check_file_exist(binfile): continue
					if not ledt.asm_search(asmcode,binfile):continue
			else:
				print Usage
				continue

		except KeyboardInterrupt,e:
			print '\ntype \"back\" to top level\n'
			continue



def funcsearch_shell(ledt):
	offset_scope = {}
	Usage = 'Usage:\tfuncsearch binfile funcname\ne.g.\tfuncsearch libc.so  system\n'
	print Usage

	while True:
		try:
			input = raw_input(config.Option.get("title") % 'funcsearch')
			search = " ".join((input).strip().split()).split(' ')
			if search[0] in ['back','exit','quit','q']:
				break
			elif search[0] in ['?','help']:
				print Usage
				continue	
			elif search[0]== 'funcsearch':
				p = re.compile("(funcsearch)\s*([^\s]*)\s*([^\s]*)\s*")
        			matches = p.findall(input)
				if matches:
					search = matches[0]
					if len(search[2]) <= 0:
						print Usage
						continue
 					binfile = search[1].strip()
					funcname = search[2].strip()
					if not check_file_exist(binfile): continue
					if not ledt.funcsearch_wrapper(binfile,funcname):continue
			else:
				print Usage
				continue

		except KeyboardInterrupt,e:
			print '\ntype \"back\" to top level\n'
			continue


