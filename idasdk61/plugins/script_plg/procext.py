import idaapi

"""
    This is a sample plugin for extending processor modules

    It extends the IBM PC processor module to disassemble

        int 80h
    as

        call_linux_kernel

    for ELF files

(c) Hex-Rays
"""

NN_kernel_call = idaapi.CUSTOM_CMD_ITYPE

#--------------------------------------------------------------------------
class linux_idp_hook_t(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)
        self.cmd = idaapi.cmd

    def custom_ana(self):
        if idaapi.get_many_bytes(self.cmd.ea, 2) != "\xCD\x80":
            return False

        self.cmd.itype = NN_kernel_call
        self.cmd.size = 2

        return True

    def custom_mnem(self):
        if self.cmd.itype == NN_kernel_call:
            return "linux_kernel_call"
        else:
            return None

#--------------------------------------------------------------------------
class linuxprocext_t(idaapi.plugin_t):
    # Processor fix plugin module
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Replaces int 0x80 with linux_kernel_call"
    wanted_name = "linux_kernel_call"

    def init(self):
        self.prochook = None
        if idaapi.ph_get_id() != idaapi.PLFM_386 or idaapi.cvar.inf.filetype != idaapi.f_ELF:
            print "linuxprocext_t.init() skipped!"
            return idaapi.PLUGIN_SKIP

        self.prochook = linux_idp_hook_t()
        self.prochook.hook()

        print "linuxprocext_t.init() called!"
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        print "linuxprocext_t.term() called!"
        if self.prochook:
            self.prochook.unhook()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return linuxprocext_t()
