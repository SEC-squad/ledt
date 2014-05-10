###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################

	
	[LEDT]    
	assemble/disassemble/ropseach using nasm/ndisassm

	[Commands]
	help		: help for LEDT
	assemble	: Assemble binary using nasm
	disas		: Disassemble  using ndisassm
	asmsearch	: Search asmcode in binaryfile
	ropsearch	: Search rop gadgets endding by 'ret' in binaryfile
	funcsearch	: Search fucntion offset in binaryfile
	shellcode	: Generate linux/x86 shellcode
	pattern		: Generate, search a Metasploit  cyclic pattern
	reset		: reset terminal
	banner		: show banner	
	exit		: Quit LEDT



[assemble]



[disas]


[asmsearch]




[ropsearch]

	search gadgets ndding by 'ret' in binaryfile not in memory, just an elf file on disk, it's useful


	e.g:

	ropsearch "ret" /root/Desktop/libc.so.6.1

	ropsearch "sub eax,ecx" /root/Desktop/libc.so

	ropsearch "jmp esp" /root/Desktop/libc.so
	ropsearch "jmp eax" /root/Desktop/libc.so

	ropsearch "call eax" /root/Desktop/libc.so.


	ropsearch "xor eax,eax" /root/Desktop/libc.so



[funcsearch]


[shellcode]


[pattern]

