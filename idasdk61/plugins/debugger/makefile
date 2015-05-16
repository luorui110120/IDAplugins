# first build win32 local debugger plugin
PROC=win32_user

!ifdef __CEARM__
!undef ALLDIRS
DONT_BUILD_PLUGIN=1
MODULES=win32_server kdstub wincetst
!else
O1=win32_debmod
O2=pc_debmod
!if $d(__X64__) || !$d(__EA64__)
SERVER=win32_server
!else
SERVER=         # do not build mixed servers
!endif
MODULES=cfg                         \
        win32_stub                  \
        linux_stub                  \
        armlinux_stub               \
        mac_stub                    \
        wince_stub                  \
        epoc_user                   \
        iphone_stub                 \
        chktrk
!endif
O3=debmod
!ifdef ENABLE_LOWCNDS
O4=idcfuncs
!endif
O5=win32_server_stub
ADDITIONAL_GOALS=$(ALLDIRS) $(SERVER) $(MODULES)

!include ..\plugin.mak
!ifndef LINK_NOBOR
_LDFLAGS=-dwsock32.dll          # delayed import
#!else
#_LDFLAGS=/delayload:wsock32.dll /defaultlib:delayimp.lib /delay:nobind
!endif

!ifdef ENABLE_LOWCNDS
LOWCND_FLAGS=-DENABLE_LOWCNDS
LOWCND_LIBS=$(L)idc$(A)
LOWCND_OBJS=$(F)idcfuncs$(O) $(L)dbgsrv_funcs$(O)
!endif
!ifdef ENABLE_REMOTEPDB
!ifdef __VC__
OLE32=ole32.lib
!else
OLE32=ole2w32.lib
!endif
REMOTEPDB_FLAGS=-DENABLE_REMOTEPDB
REMOTEPDB_LIBS=$(L)til$(A)
REMOTEPDB_SYSLIBS=oleaut32.lib $(OLE32)
REMOTEPDB_OBJS=$(F)tilfuncs$(O)
!endif
__CFLAGS=$(LOWCND_FLAGS) $(REMOTEPDB_FLAGS) -Ibochs_ctrl/$(F)

.PHONY: $(ADDITIONAL_GOALS) kdstub

!ifdef __X64__
DEFFILE=..\plugin64.def
!else
DEFFILE=..\plugin.def
!endif

RPC_COMMON=$(F)rpc_hlp$(O) $(F)rpc_engine$(O) $(F)util$(O)
STUB_COMMON=$(RPC_COMMON) $(F)rpc_client$(O) $(F)rpc_debmod$(O) $(F)debmod$(O)
SERVER_COMMON=$(F)server$(O) $(RPC_COMMON) $(F)rpc_server$(O) $(DUMB) \
              $(F)debmod$(O) $(LOWCND_OBJS)
#----------------------------------------------------------------------------
!ifdef __X64__
WIN32SERVER=$(R)win64_remote$(B)
SERVER_TRANS=$(F)tcpip$(O)
SERVER_OBJS=$(OBJ2) $(F)win32_server_impl$(O)
!else
!ifdef __CEARM__
WIN32SERVER=$(R)wince_remote_arm.dll
ARM_RTTI_LIB=ccrtrtti.lib
SERVER_TRANS=$(F)async$(O)
ACCESSCOPROC=xscale\$(F)accesscoproc$(O)
SERVER_OBJS=$(ACCESSCOPROC) $(F)wince_debmod$(O) $(F)arm_debmod$(O)
CREATE_DLL=/LD
CCL_LNK_OPT=/implib:$(OBJDIR)\wince_remote_arm.lib
kdstub $(ACCESSCOPROC):
	@cd xscale
	@$(MAKE)
	@cd ..

wincetst: wincetst.exe
wincetst.exe: $(F)wincetst$(O) $(F)winceasm$(O)
	$(CCL) $(OUTSW)$@ $(F)wincetst$(O) $(F)winceasm$(O) $(L)pro$(A) $(C_LIB) $(ARM_RTTI_LIB)
        $(_ARMASM) -o $@ $?
!else
WIN32SERVER=$(R)win32_remote$(B)
SERVER_TRANS=$(F)tcpip$(O)
SERVER_OBJS=$(OBJ2) $(F)win32_server_impl$(O)
!endif
!endif
WIN32_REMOTE_OBJ=$(SERVER_TRANS) $(SERVER_OBJS) $(SERVER_COMMON) \
                 $(REMOTEPDB_OBJS) $(F)win32_debmod$(O)
win32_server: $(WIN32SERVER)

$(WIN32SERVER): $(WIN32_REMOTE_OBJ) $(LOWCND_LIBS) $(REMOTEPDB_LIBS) $(L)pro$(A)
!ifdef LINK_NOBOR
        $(CCL) $(CREATE_DLL) $(OUTSW)$@ $(WIN32_REMOTE_OBJ) $(LOWCND_LIBS) $(REMOTEPDB_LIBS) $(L)pro$(A) $(C_LIB) $(ARM_RTTI_LIB) $(REMOTEPDB_SYSLIBS)
!ifndef CCL_LNK_OPT
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!endif
!else
        $(LINKER) $(C_STARTUP) $(WIN32_REMOTE_OBJ),$@,,$(LOWCND_LIBS) $(REMOTEPDB_LIBS) $(REMOTEPDB_SYSLIBS) $(L)pro$(A) $(C_LIB)
!endif

#----------------------------------------------------------------------------
WIN32_STUB_OBJ=$(F)win32_rstub$(O) $(F)tcpip$(O) $(F)win32_server_stub$(O) $(STUB_COMMON)
WIN32CLIENT=$(BIN_PATH)win32_stub$(PLUGIN)
win32_stub: $(WIN32CLIENT)

$(WIN32CLIENT): $(WIN32_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(WIN32_STUB_OBJ) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(WIN32_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

#----------------------------------------------------------------------------
WINCE_STUB_OBJ=$(F)wince_rstub$(O) $(F)async$(O) $(STUB_COMMON)
WINCECLIENT=$(BIN_PATH)wince_stub$(PLUGIN)
wince_stub: $(WINCECLIENT)

$(WINCECLIENT): $(WINCE_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(WINCE_STUB_OBJ) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(WINCE_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

#----------------------------------------------------------------------------
EPOC_STUB_OBJ=$(F)epoc_user$(O) $(F)epoc_debmod$(O) $(F)arm_debmod$(O) $(F)debmod$(O)
EPOCCLIENT=$(BIN_PATH)epoc_user$(PLUGIN)
epoc_user: $(EPOCCLIENT)

$(EPOCCLIENT): $(EPOC_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(EPOC_STUB_OBJ) $(IDALIB) user32.lib advapi32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(EPOC_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

CHKTRK_OBJS=$(F)chktrk$(O) $(L)dumb$(O) $(L)pro$(A)
chktrk: chktrk$(B)
chktrk$(B): $(F)chktrk$(O)
!ifdef LINK_NOBOR
        $(CCL) $(OUTSW)$@ $(CHKTRK_OBJS) advapi32.lib
!else
        $(LINKER) $(C_STARTUP) $(CHKTRK_OBJS),$@,,$(C_LIB)
!endif
#----------------------------------------------------------------------------
$(F)symmacho$(O): $(I)area.hpp $(I)diskio.hpp $(I)fpro.h $(I)kernwin.hpp    \
	          $(I)llong.hpp $(I)netnode.hpp $(I)pro.h                   \
	          ../../ldr/mach-o/common.cpp ../../ldr/mach-o/common.h     \
	          symelf.hpp symmacho.cpp symmacho.hpp
!ifdef __VC__
        $(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -I../../ldr/mach-o/vc_h -D__arm__ symmacho.cpp
!else
        $(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -D__arm__       symmacho.cpp
!endif

LINUX_STUB_OBJ=$(F)linux_rstub$(O) $(F)tcpip$(O) $(STUB_COMMON)
LINUXCLIENT=$(BIN_PATH)linux_stub$(PLUGIN)
linux_stub: $(LINUXCLIENT)

$(LINUXCLIENT): $(LINUX_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(LINUX_STUB_OBJ) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(LINUX_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

#----------------------------------------------------------------------------
ARM_LINUX_STUB_OBJ=$(F)armlinux_rstub$(O) $(F)tcpip$(O) $(STUB_COMMON)
ARM_LINUXCLIENT=$(BIN_PATH)armlinux_stub$(PLUGIN)
armlinux_stub: $(ARM_LINUXCLIENT)

$(ARM_LINUXCLIENT): $(ARM_LINUX_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(ARM_LINUX_STUB_OBJ) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(ARM_LINUX_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

#----------------------------------------------------------------------------
MAC_STUB_OBJ=$(F)mac_rstub$(O) $(F)tcpip$(O) $(F)symmacho$(O) $(STUB_COMMON)
MACCLIENT=$(BIN_PATH)mac_stub$(PLUGIN)
mac_stub: $(MACCLIENT)

$(MACCLIENT): $(MAC_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(MAC_STUB_OBJ) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(MAC_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

$(F)mac_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp async.h            \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_pc.hpp debmod.h mac_local_impl.cpp mac_rstub.cpp      \
	          pc_local_impl.cpp rapi/rapi.h rpc_client.h rpc_debmod.h   \
	          rpc_engine.h rpc_hlp.h tcpip.h
        $(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -D__i386__ mac_rstub.cpp


#----------------------------------------------------------------------------
IPHONE_STUB_OBJ=$(F)iphone_rstub$(O) $(F)tcpip$(O) $(STUB_COMMON)
IPHONECLIENT=$(BIN_PATH)iphone_stub$(PLUGIN)
iphone_stub: $(IPHONECLIENT)

$(IPHONECLIENT): $(IPHONE_STUB_OBJ) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(IPHONE_STUB_OBJ) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(IPHONE_STUB_OBJ)
$@

$(IDALIB) $(LIBS) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
	$(PEUTIL) -d$(DEFFILE) $@
!endif
!endif

$(F)iphone_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp                    \
	          arm_local_impl.cpp async.h common_local_impl.cpp          \
	          common_stub_impl.cpp consts.h deb_arm.hpp debmod.h        \
	          iphone_rstub.cpp mac_local_impl.cpp rapi/rapi.h           \
	          rpc_client.h rpc_debmod.h rpc_engine.h rpc_hlp.h tcpip.h
!ifdef __VC__
        $(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -D__i386__ /Fo$@ iphone_rstub.cpp
!else
        $(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -D__i386__       iphone_rstub.cpp
!endif

#----------------------------------------------------------------------------
cfg: $(C)exceptions.cfg

$(C)exceptions.cfg:  exceptions.cfg
        $(CP) $? $@

!ifdef ALLDIRS
!include ../../alldirs.mk
!endif
# MAKEDEP dependency list ------------------
$(F)arm_debmod$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
	          $(I)netnode.hpp $(I)pro.h $(I)ua.hpp $(I)xref.hpp         \
	          arm_debmod.cpp arm_debmod.h consts.h deb_arm.hpp          \
	          debmod.h
$(F)armlinux_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp                    \
	          arm_local_impl.cpp armlinux_rstub.cpp async.h             \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp debmod.h linux_local_impl.cpp rapi/rapi.h     \
	          rpc_client.h rpc_debmod.h rpc_engine.h rpc_hlp.h tcpip.h
$(F)async$(O)   : $(I)auto.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)kernwin.hpp $(I)llong.hpp      \
	          $(I)pro.h async.cpp async.h consts.h rapi/rapi.h
$(F)chktrk$(O)  : $(I)diskio.hpp $(I)err.h $(I)fpro.h $(I)kernwin.hpp       \
	          $(I)llong.hpp $(I)pro.h chktrk.cpp metrotrk.cpp           \
	          metrotrk.h
$(F)debmod$(O)  : $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp   \
	          $(I)pro.h $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp      \
	          $(I)xref.hpp consts.h debmod.cpp debmod.h
$(F)epoc_debmod$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h      \
	          $(I)segment.hpp $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp    \
	          arm_debmod.h consts.h deb_arm.hpp debmod.h                \
	          epoc_debmod.cpp epoc_debmod.h metrotrk.cpp metrotrk.h
$(F)epoc_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp arm_debmod.h       \
	          arm_local_impl.cpp common_local_impl.cpp                  \
	          common_stub_impl.cpp consts.h deb_arm.hpp debmod.h        \
	          epoc_debmod.h epoc_local_impl.cpp epoc_user.cpp           \
	          metrotrk.h
$(F)linux_check$(O): linux_check.c
$(F)linux_debmod$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)prodir.h $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/elf/elfbase.h           \
	          android.cpp android.hpp arm_debmod.h async.h consts.h     \
	          deb_arm.hpp deb_pc.hpp debmod.h linux_debmod.cpp          \
	          linux_debmod.h linux_threads.cpp pc_debmod.h rapi/rapi.h  \
	          rpc_engine.h rpc_hlp.h rpc_server.h symelf.hpp tcpip.h
$(F)linux_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp async.h            \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_pc.hpp debmod.h linux_local_impl.cpp linux_rstub.cpp  \
	          pc_local_impl.cpp rapi/rapi.h rpc_client.h rpc_debmod.h   \
	          rpc_engine.h rpc_hlp.h tcpip.h
$(F)linux_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)err.h          \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)srarea.hpp  \
	          $(I)ua.hpp $(I)xref.hpp arm_debmod.h                      \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp deb_pc.hpp debmod.h linux_debmod.h            \
	          linux_local_impl.cpp linux_user.cpp pc_debmod.h           \
	          pc_local_impl.cpp
$(F)linux_wait$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp arm_debmod.h consts.h             \
	          deb_arm.hpp deb_pc.hpp debmod.h linux_debmod.h            \
	          linux_wait.cpp pc_debmod.h
$(F)mac_debmod$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp ../../ldr/mach-o/common.h consts.h           \
	          deb_arm.hpp deb_pc.hpp debmod.h mac_debmod.cpp            \
	          mac_debmod.h pc_debmod.h symelf.hpp symmacho.hpp
$(F)mac_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp                    \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp deb_pc.hpp debmod.h mac_debmod.h              \
	          mac_local_impl.cpp mac_user.cpp pc_debmod.h               \
	          pc_local_impl.cpp symelf.hpp symmacho.hpp
$(F)pc_debmod$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp consts.h deb_pc.hpp debmod.h      \
	          pc_debmod.cpp pc_debmod.h
$(F)rpc_client$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)name.hpp $(I)pro.h        \
	          $(I)ua.hpp $(I)xref.hpp async.h consts.h debmod.h         \
	          rapi/rapi.h rpc_client.cpp rpc_client.h rpc_engine.h      \
	          rpc_hlp.h tcpip.h
$(F)rpc_debmod$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)segment.hpp     \
	          $(I)ua.hpp $(I)xref.hpp async.h consts.h debmod.h         \
	          rapi/rapi.h rpc_client.h rpc_debmod.cpp rpc_debmod.h      \
	          rpc_engine.h rpc_hlp.h tcpip.h
$(F)rpc_engine$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)ua.hpp          \
	          $(I)xref.hpp async.h consts.h debmod.h rapi/rapi.h        \
	          rpc_engine.cpp rpc_engine.h rpc_hlp.h tcpip.h
$(F)rpc_hlp$(O) : $(I)area.hpp $(I)bytes.hpp $(I)expr.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp consts.h          \
	          rpc_hlp.cpp rpc_hlp.h
$(F)rpc_server$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp   \
	          $(I)pro.h $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp      \
	          $(I)xref.hpp async.h consts.h debmod.h rapi/rapi.h        \
	          rpc_engine.h rpc_hlp.h rpc_server.cpp rpc_server.h        \
	          tcpip.h
$(F)server$(O)  : $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)ua.hpp          \
	          $(I)xref.hpp async.h consts.h debmod.h rapi/rapi.h        \
	          rpc_engine.h rpc_hlp.h rpc_server.h server.cpp tcpip.h
$(F)symelf$(O)  : $(I)area.hpp $(I)diskio.hpp $(I)expr.hpp $(I)fpro.h       \
	          $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)pro.h $(I)ua.hpp $(I)xref.hpp           \
	          ../../ldr/elf/common.cpp ../../ldr/elf/elf.h              \
	          ../../ldr/elf/elfbase.h ../../ldr/elf/elfr_arm.h          \
	          ../../ldr/elf/elfr_ia6.h consts.h debmod.h symelf.cpp     \
	          symelf.hpp
$(F)tcpip$(O)   : $(I)err.h $(I)expr.hpp $(I)kernwin.hpp $(I)llong.hpp      \
	          $(I)pro.h consts.h tcpip.cpp tcpip.h
$(F)util$(O)    : $(I)area.hpp $(I)expr.hpp $(I)fpro.h $(I)ida.hpp          \
	          $(I)idd.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)pro.h $(I)ua.hpp $(I)xref.hpp consts.h debmod.h       \
	          util.cpp
$(F)win32_debmod$(O): $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)dbg.hpp       \
	          $(I)diskio.hpp $(I)err.h $(I)exehdr.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp          \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
	          $(I)prodir.h $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp      \
	          ../../ldr/pe/common.cpp ../../ldr/pe/common.h             \
	          ../../ldr/pe/pe.h arm_debmod.h async.h consts.h           \
	          deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h rapi/rapi.h   \
	          rpc_engine.h rpc_hlp.h rpc_server.h tcpip.h               \
	          win32_debmod.cpp win32_debmod.h win32_debmod_impl.cpp     \
	          win32_rpc.h win32_undoc.h win32_util_impl.cpp wince.hpp   \
	          wince_debmod.h wince_debmod_impl.cpp xscale/breakpoint.h
$(F)win32_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h  \
	          async.h common_local_impl.cpp common_stub_impl.cpp        \
	          consts.h deb_pc.hpp debmod.h pc_local_impl.cpp            \
	          rapi/rapi.h rpc_client.h rpc_debmod.h rpc_engine.h        \
	          rpc_hlp.h tcpip.h win32_local_impl.cpp win32_rpc.h        \
	          win32_rstub.cpp
$(F)win32_server_impl$(O): $(I)area.hpp $(I)bytes.hpp $(I)expr.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp                   \
	          $(EXTRADEPS) ../../ldr/pe/pe.h arm_debmod.h               \
	          consts.h deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h      \
	          rpc_hlp.h win32_debmod.h win32_rpc.h                      \
	          win32_server_impl.cpp wince.hpp wince_debmod.h
$(F)win32_server_stub$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h    \
	          consts.h deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h      \
	          win32_debmod.h win32_server_stub.cpp wince.hpp            \
	          wince_debmod.h
$(F)win32_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)err.h          \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)srarea.hpp  \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h    \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h               \
	          pc_local_impl.cpp rpc_hlp.h win32_debmod.h                \
	          win32_local_impl.cpp win32_rpc.h win32_user.cpp           \
	          wince.hpp wince_debmod.h
$(F)wince_debmod$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)ua.hpp          \
	          $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h async.h       \
	          consts.h deb_arm.hpp debmod.h rapi/rapi.h rpc_engine.h    \
	          rpc_hlp.h rpc_server.h tcpip.h wince.hpp                  \
	          wince_debmod.cpp wince_debmod.h xscale/breakpoint.h
$(F)wince_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h  \
	          arm_local_impl.cpp async.h common_local_impl.cpp          \
	          common_stub_impl.cpp consts.h deb_arm.hpp debmod.h        \
	          rapi/rapi.h rpc_client.h rpc_debmod.h rpc_engine.h        \
	          rpc_hlp.h tcpip.h win32_local_impl.cpp win32_rpc.h        \
	          wince.hpp wince_rstub.cpp
