#-------------------------------------------------------------------------------
# Name:        importSym
# Purpose:
#
# Author:      KD
#
# Created:     06-20-2015
# Copyright:   (c) KD 2015
# Licence:     improt boot-kernle kallsyms
#-------------------------------------------------------------------------------
from idaapi import *
import idc
class KDimportSysmplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "import boot kernel sysm --KD"

    help = "http://bbs.chinapyg.com/"
    wanted_name = "Import Sysm plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        index = 0;
        baseaddr = 0;
        filepath = AskFile(0, "*.*", "")
        if(filepath):
            fr=open(filepath,"r")
            for i in fr:
                Lstr= i.rstrip().split(' ')
                addr = int(Lstr[0], 16)
                if(0 == baseaddr):
                    if( Lstr[2].find("stext") >= 0):
                        baseaddr = addr;
                        if(baseaddr != get_imagebase()):
                         set_imagebase(baseaddr)
                if addr >= baseaddr and (Lstr[1] == 'T' or Lstr[1] == 't'):
                 index += 1
                 if GetFunctionAttr(addr, FUNCATTR_START) == -1:
                     MakeFunction(addr,-1)
                 if 0 == MakeNameEx(addr, Lstr[2], SN_NOCHECK|SN_NOWARN):
                    idaapi.msg("Fial! index:%d, addr :%08X, %s\n"%(index, addr, Lstr[2]))
        else:
            idaapi.msg("nofind\n")

    def term(self):
        idaapi.msg("term() success!\n")

def PLUGIN_ENTRY():
    return KDimportSysmplugin_t()
