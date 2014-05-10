###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################

try:
	import os
	import sys
	import tempfile
	import struct
	import string
	import config
	from utils import *
	from interact_shell import *
	from socket.tcp_socket_serv import *
	from socket.tcp_socket_cli import *
except Exception,e:
	print e

#text section base address
SECTION_BASE_ADDR = 0x00000000
#text section offset 
SECTION_OFFSET = 0x00000000

BUFFER_SIZE = 1024

#######################################################

#LEDT class 
class LEDT(object):
	"""
	[LEDT]    	Linux Exploit Development Tool
			
	[Commands]
	help		: TIY
	assemble	: Assemble using nasm
	disas		: Disassemble  using ndisassm
	asmsearch	: Search asmcode in binaryfile
	ropsearch	: Search rop gadgets endding by 'ret' in binaryfile
	funcsearch	: Search func in executable sections (.text/.plt/.init/.fini/..)
	strsearch	: Search string in data sections (.data/.rodata/..)
	libfunc_off	: Get fucntion offset in lib binaryfile
	shellcode	: Generate linux/x86 shellcode
	pattern		: Generate, search a Metasploit  cyclic pattern
	set 		: Set LEDT configuration
	reset		: reset terminal
	banner		: show banner	
	exit		: Quit LEDT
	"""

	def __init__(self):
		
		self.check_config()




	def interact_shell(self):
		interact_shell(self)


	def check_config(self):
		#check objdump

		#check elfread

		#check nasm

		#check ndisasm

		return


	def assemble(self, asmcode):
		"""
		Assemble ASM instructions using NASM
			- asmcode: input ASM instructions, multiple instructions are separated by ";" (String)
		Returns:
			- bin code (raw bytes)
		"""
		mode = config.Option.get('mode')		#mode: 16 / 32 / 64
		if mode not in [16, 32, 64]:
			print('error mode')
			exit(0)

		asmcode = asmcode.strip('"').strip("'")
		asmcode = asmcode.replace(";", "\n")
		asmcode = ("BITS %d\n" % mode) + asmcode
		asmcode = asmcode.decode('string_escape')
		infd = tmpfile()
		outfd = tmpfile()
		infd.write(asmcode)
		infd.flush()
		command = config.NASM_COMMAND_FORMAT % (config.NASM, outfd.name, infd.name)
		execute_command(command)
		
		bincode = outfd.read()
	
		if bincode == None or len(bincode) == 0 :
			print "bad asmcode!!"
			return ''
		infd.close()
		if os.path.exists(outfd.name):
			outfd.close()
		return bincode



	def disassemble_wrapper(self, bincode):
		"""
		Disassemble binary to ASM instructions using NASM
			- bincode: input binary code(raw bytes)
			- mode: 16/32/64 bits assembly

		Returns:
			- ASM code (String)
		"""
		mode = config.Option.get('mode')		#mode: 16 / 32 / 64
		if mode not in [16, 32, 64]:
			print('error mode')
			exit(0)

		command = config.NDISASM_COMMAND_FORMAT % (config.NDISASM, mode)
		disas_result = execute_command(command, bincode)

		return disas_result


	def disassemble(self,bincode):

		result = ''
		asmcode = self.disassemble_wrapper(bincode)
		reg = "[0-9a-f]{0,8}\s*[0-9a-zA-Z]*\s*(.*)"
		pattern = re.compile(reg)


		for line in asmcode.splitlines():
			m = pattern.match(line)
			if m:
				result += m.groups()[0] + "; "
		return result


	def asm_search_wrapper(self, binfile,asmcode,section_name='EXEC',section_info=[]):
		"""
		Search asm instructions

		Args:
			- asmcode: assembly instruction separated by ";" (String)
			- binfile: target binary file (String)
			- start: start address (Int)
			- end: end address (Int)
		Returns:
			- list of (address(Int), hexbyte(String))
		"""

		asmcodes = []

		if section_name == 'EXEC' and len(section_info) == 0: 	#search all executeable sections
			section_list = self.get_elf_hdr_info(binfile)
			count = len(section_list)
			if count <= 0:
				return []
			executeable_sections = self.find_executable_sections(section_list)
			for i in xrange(len(executeable_sections)):
				asmcodes += self.asm_search_wrapper( binfile,asmcode,executeable_sections[i][0],executeable_sections[i])	#recursive call
			return asmcodes

		
		offset_scope = self.locate_section_scope(section_info,section_name)
		end = offset_scope['end']
		start = offset_scope['start']

		asmcodes = self.asm_search(binfile,asmcode,section_name,section_info)

		print("-----------------------------------------------------------")
		if not asmcodes:
			print("Not found %s in section [%s]\n" % (asmcode,section_name))
			print("-----------------------------------------------------------\n")
			return [] 

		print("SECTION:\t[%s]" % section_name)
		print("VirAddr:\t[0x%08x]" % SECTION_BASE_ADDR)
		print("Offset :\t[0x%08x]" % SECTION_OFFSET)
		print("Size   :\t[0x%08x]\n" % (end - start))
		print("find %d gadgets!\n" % len(asmcodes))

		result = ''
		for (addr, code, byte) in asmcodes:
			result += "%s :\t[%s]\t(%s)\n" % (to_address(int(addr,16)), code, byte)
		result += "\n\n"
		page_output(result)
		return asmcodes

		return result


	def asm_search(self, binfile,asmcode,section_name='EXEC',section_info=[]):
		"""
		Search for asmcode given in binfile
		Args:
			- asmcode: asmcode (string)

		Returns:
			- result: all rop gadgets found (list)
		Usage:
			ropsearch asmcode  binfile [section]

		"""

		result = []

		if section_name == 'EXEC' and  len(section_info) == 0 : 	#search all executeable sections
			section_list = self.get_elf_hdr_info(binfile)
			count = len(section_list)
			if count <= 0:
				return []
			executeable_sections = self.find_executable_sections(section_list)
			for i in xrange(len(executeable_sections)):
				#recursive call
				result += self.asm_search(binfile,asmcode, executeable_sections[i][0],executeable_sections[i])	
			
			return result

		if section_name != 'EXEC' and len(section_info) == 0:
			section_info = self.get_section_info(binfile,section_name)

		search =self.assemble(asmcode.replace(";", "\n"))
		search = escapeRegExprStr(search)
		if not search:
			return False

		# search asmcode
		offset_scope = self.locate_section_scope(section_info,section_name)
		end = offset_scope['end']
		start = offset_scope['start']
		asmcodes = self.search_binfile(binfile,start, end, search)

		if len(asmcodes)==0:
			return []

		asmcodes = sorted(asmcodes, key=lambda x: len(x[1][0]))
		if not asmcodes:
			return [] 

		for (addr, byte) in asmcodes:
			result += [(to_address(addr), asmcode,byte)]

		return result



	def rop_search_wrapper(self, binfile,asmcode,section_name='EXEC',section_info=[]):
		"""
		Search for ROP gadgets(endding by 'ret' ) containes asmcode given in binfile
		Args:
			- asmcode: asmcode (string)

		Returns:
			- result: all rop gadgets found (list)
		Usage:
			ropsearch asmcode  binfile [section]

		"""

		rop_gadgets = []

		if section_name == 'EXEC' and len(section_info) == 0: 	#search all executeable sections
			section_list = self.get_elf_hdr_info(binfile)
			count = len(section_list)
			if count <= 0:
				return []
			executeable_sections = self.find_executable_sections(section_list)
			for i in xrange(len(executeable_sections)):
				rop_gadgets += self.rop_search_wrapper( binfile,asmcode,executeable_sections[i][0],executeable_sections[i])	#recursive call
			return rop_gadgets

		
		offset_scope = self.locate_section_scope(section_info,section_name)
		end = offset_scope['end']
		start = offset_scope['start']

		rop_gadgets = self.rop_search(binfile,asmcode,section_name,section_info)

		print("-----------------------------------------------------------")
		if not rop_gadgets:
			print("Not found %s gadgets in section [%s]\n" % (asmcode,section_name))
			print("-----------------------------------------------------------\n")
			return [] 

		print("SECTION:\t[%s]" % section_name)
		print("VirAddr:\t[0x%08x]" % SECTION_BASE_ADDR)
		print("Offset :\t[0x%08x]" % SECTION_OFFSET)
		print("Size   :\t[0x%08x]\n" % (end - start))
		print("find %d gadgets!\n" % len(rop_gadgets))

		result = ''
		for (addr, byte, code) in rop_gadgets:
			#result += "%s :\t[%s]\t(%s)\n" % (to_address(int(addr,16)), byte, code)
			result += "%s :\t[%s]\n" % (to_address(int(addr,16)), byte)
		result += "\n\n"
		page_output(result)
		return rop_gadgets


	def rop_search(self, binfile,asmcode,section_name='EXEC',section_info=[]):
		"""
		Search for ROP gadgets(endding by 'ret' ) containes asmcode given in binfile
		Args:
			- asmcode: asmcode (string)

		Returns:
			- result: all rop gadgets found (list)
		Usage:
			ropsearch asmcode  binfile [section]

		"""

		result = []

		if section_name == 'EXEC' and  len(section_info) == 0 : 	#search all executeable sections
			section_list = self.get_elf_hdr_info(binfile)
			count = len(section_list)
			if count <= 0:
				return []
			executeable_sections = self.find_executable_sections(section_list)
			for i in xrange(len(executeable_sections)):
				#recursive call
				result += self.rop_search(binfile,asmcode, executeable_sections[i][0],executeable_sections[i])	
			
			return result

		if section_name != 'EXEC' and len(section_info) == 0:
			section_info = self.get_section_info(binfile,section_name)

		offset_scope = self.locate_section_scope(section_info,section_name)
		end = offset_scope['end']
		start = offset_scope['start']

		rop_gadgets = self.rop_gadgets_search(asmcode, binfile,start, end)
		rop_gadgets = sorted(rop_gadgets, key=lambda x: len(x[1][0]))
		if not rop_gadgets:
			return [] 

		for (addr, (byte, code)) in rop_gadgets:
			#result += "%s :  [%s]  (%s)\n" % (to_address(int(addr,16)), (code), (byte))
			result += [(to_address(int(addr,16)), code,byte)]

		return result


	def rop_gadgets_search(self, asmcode, binfile, start, end):
		"""
		Search rop gadgets endding by ret in binfile

		Args:
			- asmcode: assembly instruction separated by ";" (String)
			- binfile: target binary file (String)
			- start: start address (Int)
			- end: end address (Int)
		Returns:
			- list of (address(Int), hexbyte(String))
		"""

		#nasm syntax
		asmcode = asmcode.replace(";", "\n")
		search =self.assemble(asmcode)
		search = escapeRegExprStr(search)
		if not search:
			return False
		
		#rop_search_bytes = search_bytes
		search += "(.){0,"+str(config.Option.get("search_bytes"))+"}\\xc3"	

		# search ROP gadgets ending by RET
		rop_gadgets = self.search_binfile(binfile,start, end, search)

		result = {}
		for (a, v) in rop_gadgets:
			gadget = self.check_rop_gadget(binfile,a, a+len(v)/2 )
			# gadget format: [(address, bytes,asmcode ), (address, bytes,asmcode ), ...]
			if gadget != []:
				bytes = ""
				asmcode = ""
				addr = gadget[0][0]
				if SECTION_BASE_ADDR > SECTION_OFFSET:
					if not config.Option.get('show_virtual'):
						addr = str(int(addr,16) - SECTION_BASE_ADDR)	
				for (_, b, c) in gadget:
					bytes += b
					asmcode += c + "; "
				if addr not in result:
					result[addr] = (bytes, asmcode)

		result = result.items()

		return result



	def funcsearch_wrapper(self, binfile, funcname, section_name = 'EXEC',exactly=False,section_info=[]):

		'''
			setction info's format is (name,VritualAddr,Offset,Size,flags)
		'''

		fucn_info = []
		if section_name == 'EXEC' and len(section_info) == 0: 	#search all executeable sections
			section_list = self.get_elf_hdr_info(binfile)
			count = len(section_list)
			if count <= 0:
				return []
			executeable_sections = self.find_executable_sections(section_list)
			for i in xrange(len(executeable_sections)):
				#recursive call
				fucn_info += self.funcsearch_wrapper(binfile, funcname, executeable_sections[i][0],exactly,executeable_sections[i])
	
			return fucn_info

		if section_name != 'EXEC' and len(section_info) == 0:
			section_info = self.get_section_info(binfile,section_name)

		offset_scope = self.locate_section_scope(section_info,section_name)
		end = offset_scope['end']
		start = offset_scope['start']

		fucn_info = self.funcsearch( binfile, funcname, section_name,exactly )

		print("-----------------------------------------------------------")
		if not fucn_info:
			print("Not found fucntion: %s in section [%s]\n" % (funcname,section_name))
			print("-----------------------------------------------------------\n")
			return []
		print("SECTION:\t[%s]" % section_name)
		print("VirAddr:\t[0x%08x]" % SECTION_BASE_ADDR)
		print("Offset :\t[0x%08x]" % SECTION_OFFSET)
		print("Size   :\t[0x%08x]\n" % (end - start))
		result = ''
		for (addr, name,line) in fucn_info:
			if SECTION_BASE_ADDR > SECTION_OFFSET:
				if not config.Option.get('show_virtual'):
					addr = str(int(addr,16) - SECTION_BASE_ADDR)	
			result += "[0x%08x]\t%s\n|________________________________________%s\n\n\n" % (int(addr,16),name,line)
		result += "\n\n"
		page_output(result,config.Option.get("pagesize"),4)

		return fucn_info


	def funcsearch(self, binfile, funcname, section_name = 'EXEC',exactly = False):

		'''
			Search fucntion in all executable sections (.text/.plt/.init/.fini/..)

			if section_name = 'EXEC' , it will search all executable sections
			normally includeing .text / .init / .fini /.plt 

			return:
				fucn_info : [((addr1,funcname1),info1),((addr2,funcname2),info2),...]

		'''

		fucn_info = []

		if section_name == 'EXEC': 	#search all executeable sections
			section_list = self.get_elf_hdr_info(binfile)
			count = len(section_list)
			if count <= 0:
				return []
			executeable_sections = self.find_executable_sections(section_list)
			for i in xrange(len(executeable_sections)):
				#recursive call
				fucn_info += self.funcsearch(binfile, funcname,executeable_sections[i][0],exactly)	

			return fucn_info

		asm_result = self.objdump_section(binfile,  section_name)

		if not asm_result:
			return []

		#0002f550 <exit>:
		#0002f580 <on_exit>:
		reg = '([0-9a-f]{0,8})\s*<(%s)>\s*:' % funcname if exactly else \
			  '([0-9a-f]{0,8})\s*<(.*%s.*)>\s*:' % funcname

		pattern = re.compile(reg)
		 
		for line in asm_result.splitlines():
			m = pattern.match(line)
			if m:
				(addr,name) = m.groups()
				fucn_info += [(to_address(int(addr,16)),name,line)]

		return fucn_info if len(fucn_info) else []



	def str_search(self,binfile,str):
		'''	
			search for str endding by null in binfile

			Returns:
				result : format [offset,str,hexstr]
					     offset (int)
					     str 	(String)
					     hexstr (String)
		'''	
		section_list = self.get_elf_hdr_info(binfile)

 		data_sections = self.find_data_sections(section_list)

 		count = len(data_sections)
 		if count == 0 :
 			return []

 		result = []
 		for i in xrange(count):
 			offset_scope = self.locate_section_scope(data_sections[i],data_sections[i][0])
			end = offset_scope['end']
			start = offset_scope['start']

			#search string
			search = "%s\\x00" % str
			strings = self.search_binfile(binfile,start, end, search)
			for i in xrange(len(strings)):
				(offset,hexstr) = strings[i]
				str = ''
				for j in xrange(0,len(hexstr),2):
					c = hexstr[j]
					c += hexstr[j+1]
					str += struct.pack('b',int(c,16))

				result.append( (offset, str, hexstr) )

		return result


	def libfunc_offset(self,libpath,funcname):
		'''
		Args:
			libpath  : lib file path 
			funcname : function name
		Returns:
			offset   : funcname offset in libfile

		'''
		offset = ''
		if check_file_exist(libpath):
			command = config.LIBFUNC_OFFSET + config.LIBFUNC_OFFSET_FORMAT %\
					  (libpath,funcname)
			offset = execute_command(command)
			
			if len(offset) > 0:
				return int(offset,16)
			else:
				return 0

	def check_sec(self,binpath):
		'''
		Args:
			binpath  : target binary file
		Returns:
			result   : memory protection informations

		'''
		result = ''
		if check_file_exist(binpath):
			command = config.CHECK_SEC + config.CHECK_SEC_FORMAT % (binpath)
			result = execute_command(command)
			return result


	def search_binfile(self,binfile,start, end, search):
		"""
		Search for all instances of a pattern in search_binfile from start to end

		Args:
				- binfile: target binary file
				- start: start address (Int)
				- end: end address (Int)
				- search: string or python regex pattern (String)

		Returns:
				- list of found result: (address(Int), hex encoded value(String))
		"""

		result = []

		if end == start == 0:
			return []

		if end < start:
				(start, end) = (end, start)

		hexdata = self.dump_file(binfile,start, end)
		if hexdata is None:
			print "error: dumpfile %s" % binfile
			return result
		try:
				p = re.compile(search)
		except:
				print "search pattern contains unescape char!!"
				print "search pattern : %s" % search
				return []

		found = p.finditer(hexdata)
		found = list(found)
		for m in found:
				result += [(start + m.start(), hexdata[m.start():m.end()].encode('hex'))]

		return result


	def dump_file(self,filepath,offset_start,offset_end):
		hexdata = ''
		try:
			fd = open(filepath,'r')
			fd.seek(offset_start,0)
			hexdata = fd.read(offset_end-offset_start)
			fd.close()
		except Exception,e:
			print "error: %s\n",e
			return None				

		return hexdata


	def get_elf_hdr_info(self,binfile):
		'''

		Returns :
			section_list contains  setction info in binfile
			each setction info's format is (name,VritualAddr,Offset,Size,flags)

		'''
		command = config.READELF_COMMAND_FORMAT % (config.READELF,binfile)
		#print command
		elf_hdr_info = execute_command(command)
		if len(elf_hdr_info) == 0:
			print "error: get elf headers info of \"%s\"\n" % binfile
			return None

		if len(elf_hdr_info) <= 0:
			printf("error: no data to paser!")
			return None
		#search section 
		reg = "[^\.^_]*\s*([^\s]*).*([0-9a-f]{8})\s*([0-9a-f]{6})\s*([0-9a-f]{6})\s*([0-9]{0,4})\s*([a-zA-Z]*).*"
		section_list = []
		pattern = re.compile(reg)
		for line in elf_hdr_info.splitlines():
			m = pattern.match(line)
			if m:
				(name,VritualAddr,Offset,Size,_,flags) = m.groups()
				section = (name,VritualAddr,Offset,Size,flags)
				section_list.append(section)

		return section_list


 	def get_section_info(self,binfile,section_name):
		'''
			sections_list contains  setction info
			setction info's format is (name,VritualAddr,Offset,Size,flags)

		'''
		section_info = []
		section_list = self.get_elf_hdr_info(binfile)
		count = len(section_list)
		if count <= 0:
			return []
		for i in xrange(count):
			if section_name == section_list[i][0]:
				#print("section[%s] is executable!" % section_list[i][0])
				return section_list[i]

		return []


	def find_executable_sections(self,section_list):
		'''
			sections_list contains  setction info
			each setction info's format is (name,VritualAddr,Offset,Size,flags)

		flag:

		 W (write), A (alloc), X (execute), M (merge), S (strings)
		  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
		  O (extra OS processing required) o (OS specific), p (processor specific)
		e.g:
			[14] .text             PROGBITS        08049f00 001f00 0118fc 00  AX  0   0 16

		'''
		exec_sections = []
		count = len(section_list)
		if count == 0 :
			return []
		for i in xrange(count):
			if 'X' in section_list[i][4]:
				#print("section[%s] is executable!" % section_list[i][0])
				exec_sections.append(section_list[i])

		return exec_sections



	def find_data_sections(self,section_list):
		'''
			sections_list contains  setction info
			each setction info's format is (name,VritualAddr,Offset,Size,flags)

		'''
		data_sections = []
		count = len(section_list)
		if count == 0 :
			return []
		for i in xrange(count):
			if 'X' not in section_list[i][4]:
				data_sections.append(section_list[i])

		return data_sections


	def locate_section_scope(self,section_info,section_name='.text'):
		"""
		find section offset scope using readelf / objdump

		Args:
			- setction_info's format is (name,VritualAddr,Offset,Size,flags)
			- section_name : elf file section name (String)
		Returns:
			- section offset scope

		"""
		global SECTION_BASE_ADDR
		global SECTION_OFFSET 

		offset_scope = {
			'start':0x00000000,
			'end' :0x00000000
		}


		Addr = int(section_info[1],16)
		Off = int(section_info[2],16) 
		Size = int(section_info[3],16) 

		if Addr > Off:
                	SECTION_BASE_ADDR = Addr
        	else:
                	SECTION_BASE_ADDR = Off

		SECTION_OFFSET = Off
		offset_scope['start'] = Off
		offset_scope['end'] =  Off + Size

		return offset_scope


	def objdump_section(self,binfile,section_name='.text'):
		'''

		'''
		command = config.OBJDUMP_SECTION_FORMAT % (config.OBJDUMP,config.Option.get("style"),section_name,binfile)
		#print command
		asm_result = execute_command(command )
		if len(asm_result) <=0 :
			return None

		return asm_result


	
	def objdump_range(self,binfile,start, end):
		'''

		'''
		command = config.OBJDUMP_RANGE_FORMAT  % (config.OBJDUMP,config.Option.get("style"),str(hex(start)),str(hex(end)),binfile)
		#print command
		asm_result = execute_command(command )
		if len(asm_result) <=0 :
			return None

		return asm_result



	def check_rop_gadget(self,binfile, start, end):
		"""
		Verify ROP gadget code from start to end with max number of instructions

		Args:
			- binfile: target binary file(String)
			- start: start address (Int)
			- end: end addres (Int)

		Returns:
			- list of valid gadgets (address(Int), bytes(String), asmcode(String))
		"""
		result = []

		if SECTION_BASE_ADDR > SECTION_OFFSET:
                	end = SECTION_BASE_ADDR + (end - SECTION_OFFSET)
                	start = SECTION_BASE_ADDR + (start - SECTION_OFFSET)

		asm_result = self.objdump_range(binfile, start, end)

		if not asm_result:
			return None

		#  10662e:	ff e0                	jmp    *%eax
		#  106630:	5b                   	pop    %ebx
		#  106631:	5e                   	pop    %esi
		#  106632:	5d                   	pop    %ebp
		#  106633:	c3                   	ret    
		pattern = re.compile("\s*([0-9a-f]{0,8}):\t*([^\t]*)\t*(.*)")
		matches = pattern.findall(asm_result)
		for line in asm_result.splitlines():
			m = pattern.match(line)
			if m:
				(addr, bytes, asmcode) = m.groups()
				bytes = '\\x'.join(bytes.strip().split(' '))
				bytes = '\\x' + bytes
				asmcode = " ".join(asmcode.strip().split())
				if "bad" not in asmcode:
					result += [(addr,bytes, asmcode )]
					if "ret" in asmcode:
						return result
		return []



	def shellcode_format(self,asmcode):
		"""
		Format raw shellcode to ndisasm output display
			"\x6a\x01"  	# 0x00000000 	push byte +0x1
			"\x5b"	  	# 0x00000002 	pop ebx
		"""

		if not asmcode:
			return ""


		mode = config.Option.get('mode')		#mode: 16 / 32 / 64
		if mode not in [16, 32, 64]:
			print('error mode')
			exit(0)

		shellcode = []
		# e.g: 00000000  50                push eax
		pattern = re.compile("([0-9A-F]{8})\s*([^\s]*)\s*(.*)")

		matches = pattern.findall(asmcode)
		for line in asmcode.splitlines():
			m = pattern.match(line)
			if m:
				(addr, bytes, code) = m.groups()
				sc = '"%s"' % to_hexstr(bytes.decode('hex'))
				shellcode += [(sc, "0x"+addr, code)]
		maxlen = max([len(x[0]) for x in shellcode])
		output = ''
		for (sc, addr, code) in shellcode:
			output += "%s	# %s	%s\n" % (sc.ljust(maxlen+1), addr, code)
		return output



	
	client = ''
	def send(self,ip,port,buf,bufsize=BUFFER_SIZE,protocol='tcp'):
		'''

		'''
		if protocol == 'tcp':
			self.client = TcpSocketCli()
			self.client.send(ip,port,buf,bufsize)

		elif protocol == 'udp':
			pass


	data = ''
	def read(self,bufsize=BUFFER_SIZE):
		'''
		
		'''
		self.data = self.client.read(bufsize)




	def close(self):
		'''

		'''
		self.client.close()
	


	def rasm_disassemble(self,rasmpath,asmcode,platform='x86.nasm',mode='32'):
		'''
			rasm2 -a x86.nasm -b 32  "and eax,0x11223344"

			output: 2544332211

		'''
		opcode = ''
		disas_command = '%s -a %s -b %s  \"%s\"'%(rasmpath,platform,mode,asmcode)
		#print disas_command 
		output = execute_command(disas_command)
		return output

		
	def rasm_assemble(self,rasmpath,opcode,platform='x86',mode='32'):
		'''
			rasm2 -a x86 -b 32  -d "2544332211"

			output: and eax,0x11223344

		'''
		asmcode =''
		asm_command = '%s -a %s -b %s  -d \"%s\"'%(rasmpath,platform,mode,opcode)
		#print asm_command 
		output = execute_command(asm_command)
		return output	 
	


#:)class end 
###########################################################################################################




