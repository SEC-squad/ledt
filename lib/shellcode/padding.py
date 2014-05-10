
##########################################################
#
#   padding string
#
#	                         random	     2014-04-21
##########################################################

ALIGN = 4
##########################################################

#padding FilePath with  '/'  by 4 bytes aligned
def PaddingFilepath(binpath, align = ALIGN):
		newpath = ''
		sub_path =  binpath.split('/') 
		for p in sub_path:
			if len(p):
				newpath = newpath + (align - len(p) % align) * '/'  + p
		return newpath