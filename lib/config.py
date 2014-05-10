###############################################################
#       LEDT - Linux Exploit Development Tool
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################


BANNER = \
'''
 /$$$$$$$                            /$$                        
 | $$__  $$                          | $$                        
 | $$  \ $$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$/$$$$ 
 | $$$$$$$/ |____  $$| $$__  $$ /$$__  $$ /$$__  $$| $$_  $$_  $$
 | $$__  $$  /$$$$$$$| $$  \ $$| $$  | $$| $$  \ $$| $$ \ $$ \ $$
 | $$  \ $$ /$$__  $$| $$  | $$| $$  | $$| $$  | $$| $$ | $$ | $$
 | $$  | $$|  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$/| $$ | $$ | $$
 |__/  |__/ \_______/|__/  |__/ \_______/ \______/ |__/ |__/ |__/

                                                      @Sigma-team
'''



#tools dir
TOOLS   = r'../tools/' 
BIN     = TOOLS + r'/bin/' 
SHELL   = TOOLS + r'/sh/' 


# external binaries
NASM                    = r'/usr/bin/nasm'
NDISASM                 = r'/usr/bin/ndisasm'
READELF                 = r'/usr/bin/readelf'
OBJDUMP                 = r'/usr/bin/objdump'
LIBFUNC_OFFSET          = BIN +'libfunc_offset'
CHECK_SEC               = SHELL +'checksec.sh'


#external binaries commands
STDERR_TO_NULL          = r'2>/dev/null'
NASM_COMMAND_FORMAT     = r'%s -f bin -o %s %s ' + STDERR_TO_NULL
NDISASM_COMMAND_FORMAT  = r'%s -b %d - ' + STDERR_TO_NULL
READELF_COMMAND_FORMAT  = r'%s -S %s  ' + STDERR_TO_NULL
OBJDUMP_RANGE_FORMAT    = r'%s -d -M %s --start-address=%s --stop-address=%s %s ' + STDERR_TO_NULL
OBJDUMP_SECTION_FORMAT  = r'%s -d -M %s -j %s %s ' + STDERR_TO_NULL
LIBFUNC_OFFSET_FORMAT   = r' %s  %s'
CHECK_SEC_FORMAT        = r' --file %s'




# NEDT global options
OPTIONS = {
"mode"              :   (32, "mode: 16/32/64 bits assembly"),
"search_bytes"  	:	(16, "rop gadgets search depth, 16 bytes at most"),
"pagesize"		    :	(20, "number of lines to display per page, 0 = disable paging"),
"style"             :	("intel", "assemble style for objdump \"-M\" option, intel or att "),
"title"             :	("%s  > ", "command dash info"),
"debug"             :   (False, "debug mode"),
"show_virtual"      :   (False, "display virtual address")
}


class Option(object):
    """
	bla bla bla .... >>!
    """
    options = OPTIONS.copy()

    def __init__(self):
        pass

    @staticmethod
    def reset():
        Option.options = OPTIONS.copy()
        return True

    @staticmethod
    def show(name=""):
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][0]
        return result

    @staticmethod
    def get(name):
        if name in Option.options:
            return Option.options[name][0]
        else:
            return None

    @staticmethod
    def set(name, value):
        if name in Option.options:
            Option.options[name] = (value, Option.options[name][1])
            return True
        else:
            return False

    @staticmethod
    def help(name=""):
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][1]
        return result
