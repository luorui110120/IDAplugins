#
#       Common part of make files for IDA for MS Windows.
#
#       All makesfiles are prepared to be used by Borland's MAKE.EXE

# Main IDA directory. PLEASE EDIT OR SET ENVVAR!
!ifndef IDA
IDA=Z:\idasrc\sdk\  		# with the trailing backslash!
!endif

!include $(IDA)makeopts.mk
!include $(IDA)defaults.mk

_MKFLG=-$(MAKEFLAGS)
MAKEDEFS=$(_MKFLG:--=-) $(MAKEDEFS)

!ifdef __X64__
__EA64__=1
__VC__=1                # only Visual Studio can compile 64-bit
!endif

!ifdef __CEARM__
__VC__=1                # wince can be built only with visual studio
!endif

# since we can not debug android/cearm servers, there is no point in building
# them with debug info. always build the optimized version.
!if $d(__ANDROID__) || $d(__CEARM__) || $d(__ARMLINUX__)
  NDEBUG=1
  __ARM__=1       # both of them run on arm processor
!endif

!ifdef __ARM__
PROCFLAG=-D__ARM__
TARGET_PROCESSOR_MODULE=arm
!else
TARGET_PROCESSOR_MODULE=pc
!endif

!ifndef BC5_COM
BC5_COM=$(BCB)
!endif

ULINK_BCF=+$(ULNK_CFG_DIR)ulink.bc
ULINK_64F=+$(ULNK_CFG_DIR)ulink.vx
ULINK_VCF=+$(ULNK_CFG_DIR)ulink.v9

!ifdef __X64__
ULNK_CFG=$(ULINK_64F)
!elseif defined(__VC__)
ULNK_CFG=$(ULINK_VCF)
!else
ULNK_CFG=$(ULINK_BCF)
!endif

ULNK_COMPAT=-O- -o- -Gh -Gh-
!ifndef __X64__
ULNK_COMPAT=$(ULNK_COMPAT) -P-
!endif

ULINK=$(ULNK_BASE) $(ULNK_CFG) $(ULINK_COMPAT_OPT)

_ULCCOPT=$(_LDFLAGS) $(LNDEBUG) $(_LNK_EXE_MAP) $(_LSHOW)

!ifdef __X64__
!if "$(PROCESSOR_ARCHITEW6432)" != "AMD64"
NO_EXECUTE_TESTS = 1
!endif
!endif

!ifdef NDEBUG
OPTSUF=_opt
!endif

#-----------
!ifdef __CEARM__
LINK_NOBOR=1
!endif

!ifdef LINK_NOBOR
!undef LINK_ULINK
!endif

!ifdef __VC__
!ifndef LINK_ULINK
!undef LINK_NOBOR
LINK_NOBOR=1
!endif
!endif

!ifndef LINK_NOBOR
!ifdef MAP
_LNK_EXE_MAP=-m
!else
_LNK_EXE_MAP=-x
!endif
!else               # LINK_NOBOR
!ifdef __VC__
!ifdef MAP
_LNK_EXE_MAP=/MAP
!endif
!endif
!endif

#------
!ifndef AROPT
AROPT=ru
!endif

!ifndef NOSHOW
AROPT=$(AROPT)v
!else
.silent
_LDSW=_q

!ifdef __VC__
_CSHOW=/nologo
!else
_CSHOW=-q
!endif

!ifdef LINK_NOBOR
_LSHOW=/nologo
!else
_LSHOW=-q
!endif

_LBSHOW=_f/nologo

!endif   # NOSHOW

!ifdef SUPPRESS_WARNINGS
!ifdef __ANDROID__
  NOWARNS=-w
!elif $d(__VC__)
  NOWARNS=-w -wd4702 -wd4738
!else # BCC
  NOWARNS=-w-
!endif
!endif

######################### set TV variables
!ifndef TVSRC
  TVSRC=$(IDA)ui\txt\tv\  # TurboVision subdirectory
!endif

!ifdef _CFLAGS_TV       # set tv path(s) for ui/txt after include defaults.mk
  _CFLAGS=-I$(TVSRC)include $(_CFLAGS_TV)
!endif

############################################################################
.PHONY: all All goal Goal total Total objdir test runtest $(ADDITIONAL_GOALS)

######################### set linker debug switch
!if $d(__VC__) && !$d(LINK_ULINK)
!ifdef NDEBUG
  LNDEBUG=/DEBUG /PDB:$(F) /INCREMENTAL:NO /OPT:ICF /OPT:REF /PDBALTPATH:%_EXT%\%_PDB%
!else
  LNDEBUG=/DEBUG /PDB:$(F)
!endif
!else
!ifndef NDEBUG
  LNDEBUG=-v
!endif
!endif

#########################
# visual studio: set c runtime to use
# default is dynamic runtime
# if USE_STATIC_RUNTIME is set, use static runtime
!ifdef __VC__
!ifndef RUNTIME_LIBSW
!ifdef NDEBUG
!ifdef USE_STATIC_RUNTIME
RUNTIME_LIBSW=/MT
!else
RUNTIME_LIBSW=/MD
!endif
!else
!ifdef USE_STATIC_RUNTIME
RUNTIME_LIBSW=/MTd
!else
RUNTIME_LIBSW=/MDd
!endif
!endif
!endif
!endif

!ifdef __X64__
__EA64__=1
_SWITCH64=-D__X64__
X64SUFF=x
!endif

!ifdef __EA64__
SUFF64=64
ADRSIZE=64
SWITCH64=$(_SWITCH64) -D__EA64__
!else
ADRSIZE=32
!endif

# include,help and other directories are common for all platforms and compilers:
I =$(IDA)include\       # include directory
HO=$(R)                 # help file is stored in the bin directory
HI=$(RS)                # _ida.hlp placed in main tool directory
C =$(R)cfg\             # cfg files
RI=$(R)idc\             # idc files
HS=.hls                 #       help source
HH=.hhp                 #       help headers
SYSNAME=win

#############################################################################
# To compile debugger server for Android, Android NDK should be installed
# Environment variable ANDROID_NDK must point to it (default c:\android-ndk-r4b\)
# To cross-compile for ARM Linux/uCLinux, define SOURCERY root directory
# (default C:\CodeSourcery\Sourcery G++ Lite)
!if $d(__ANDROID__) || $d(__ARMLINUX__)
!if $d(__NT__) || $d(__VC__) || $d(__EA64__) || $d(__X64__)
!error "Please undefine __NT__, __VC__, __EA64__, __X64__to compile for Android/ARM Linux"
!endif
!ifdef NDEBUG
CCOPT=-O3 -ffunction-sections -fdata-sections
OUTDLLOPTS=-Wl,-S,-x$(DEAD_STRIP)
!else
CCOPT=-g
OUTDLLOPTS=-Wl,--strip-debug,--discard-all
!endif
BUILD_ONLY_SERVER=1
COMPILER_NAME=gcc
TARGET_PROCESSOR_NAME=arm
TARGET_PROCESSOR_MODULE=arm
!ifdef __ANDROID__
SYSNAME=android
TARGET_PLATFORM=$(SYSNAME)-8
CCDIR=$(ANDROID_NDK)build\prebuilt\windows\arm-eabi-4.4.0\bin
CCPART=arm-eabi
SYSROOT =$(ANDROID_NDK)build\platforms\$(TARGET_PLATFORM)\arch-arm
!else
!ifdef __UCLINUX__
SYSNAME=uclinux
CCPART=arm-uclinuxeabi
__EXTRADEF=-D__UCLINUX__ -fno-exceptions -Wno-psabi
__EXTRACPP=-fno-rtti
!else
SYSNAME=linux
CCPART=arm-none-linux-gnueabi
__EXTRADEF=-Wno-psabi -fexceptions
!endif
CCDIR=$(SOURCERY)\bin
SYSROOT =$(SOURCERY)\$(CCPART)\libc
!endif
CC      =$(CCDIR)\$(CCPART)-gcc.exe
CCX     =$(CCDIR)\$(CCPART)-g++.exe
SYSINC  =$(SYSROOT)\usr\include
SYSLIB  =$(SYSROOT)\usr\lib
!ifdef __ANDROID__
#BUILD_STATIC=1
!ifdef BUILD_STATIC
CRTBEGIN=$(SYSROOT)\usr\lib\crtbegin_static.o
SYS     =$(PROCFLAG) -mandroid -static
LDSTATIC=-Bstatic
!else
CRTBEGIN=$(SYSROOT)\usr\lib\crtbegin_dynamic.o
SYS     =$(PROCFLAG) -mandroid --shared
LDSTATIC=-Bdynamic
!endif
CRTEND=$(SYSROOT)\usr\lib\crtend_android.o
__EXTRADEF=-D__ANDROID__ -fno-exceptions -Wno-psabi
__EXTRACPP=-fno-rtti
!endif
STLDEFS=-D_M_ARM                        \
        -D__linux__                     \
        -D_STLP_HAS_NO_NEW_C_HEADERS    \
        -D_STLP_NO_BAD_ALLOC            \
        -D_STLP_NO_EXCEPTION_HEADER     \
        -D_STLP_USE_NO_IOSTREAMS        \
        -D_STLP_USE_MALLOC              \
        -D_STLP_UINT32_T="unsigned long"

CFLAGS=$(SYS) $(SWITCH64) $(CCOPT) -I$(I) -I$(STLDIR) -I$(SYSINC) \
        -D__ARM__                                                 \
        -D__LINUX__                                               \
        $(__EXTRADEF)                                             \
        -D_FORTIFY_SOURCE=0                                       \
        -DNO_OBSOLETE_FUNCS                                       \
        -DUSE_DANGEROUS_FUNCTIONS                                 \
        $(STLDEFS)                                                \
        -pipe -fno-strict-aliasing $(_CFLAGS)
CPPFLAGS=-fvisibility=hidden -fvisibility-inlines-hidden $(_EXTRACPP) $(CFLAGS)
OUTSW=-o #with space
OBJSW=-o #with space
STDLIBS =-lrt -lpthread
!ifdef __ANDROID__
LDFLAGS =-nostdlib $(LDSTATIC) -Wl,-dynamic-linker,/system/bin/linker -Wl,-z,nocopyreloc $(_LDFLAGS)
CCL     =$(CCX) $(LDFLAGS)
!else
LDFLAGS =-Wl,-z $(_LDFLAGS)
CCL     =$(CCX) $(LDFLAGS) $(STDLIBS)
!endif
OUTDLL  =$(SYS) -Wl,--gc-sections -Wl,--no-undefined $(OUTDLLOPTS)
LINK_NOBOR=1
B       =                                               # exe file extension
BS      =.exe                                           # host utility extension
DLLEXT  =.so
O       =.o                                             # object file extension
A       =.a                                             # library file extension
AR      =$(RS)ar$(BS) _e.at _g _l$(CCDIR)\$(CCPART)-ar.exe $(AROPT) # librarian
#############################################################################
!elif $d(__LINT__)                                      # PC-Lint
COMPILER_NAME=lint
TARGET_PROCESSOR_NAME=x86
CC      =$(PYTHON) $(RS)pclint.py
CFLAGS  =$(_CFLAGS) $(LINTFLAGS)
OUTSW   =--outdir
OBJSW   =--outdir
LINK_NOBOR=1
LINKER  =$(CC) --link
CCL     =$(CC)
AR      =$(CC) --lib
O       =.lint
B       =.lintexe
A       =.lib
R32     =$(RS)\x86_win_vc_opt\                          #
B32     =$(BS)
BS      =.exe                                           # host utility extension
#############################################################################
!elif $d(__X64__)                                       # Visual Studio 8 for AMD64
COMPILER_NAME=vc
TARGET_PROCESSOR_NAME=x64
CC      =$(MSVCDIR)bin\x86_amd64\cl.exe                 # C++ compiler
CFLAGS  =@$(IDA)$(SYSDIR).cfg $(RUNTIME_LIBSW) $(SWITCH64) $(NOWARNS) $(_CFLAGS) $(_CSHOW) # default compiler flags
!ifndef LINK_ULINK
OUTSW   =/Fe                                            # outfile name switch for one-line linker
OBJSW   =/Fo                                            # object file name switch
BASESW  =/BASE
OUTDLL  =/LD
LNOUTDLL=/DLL
!else
OUTSW   =-ZO
OUJSW   =-j
BASESW  =-b
LNOUTDLL=-Tpd+                                          # output is DLL(64) switch
OUTDLL  =-Tpd+
!endif
!ifdef BASE
LDFLAGS =$(BASESW):$(BASE) $(_LDFLAGS)
!else
LDFLAGS =$(_LDFLAGS)
!endif
_LIBRTL=$(MSVCDIR)lib\amd64
!ifndef VC_WITHOUT_PSDK
_LIBSDK=$(MSVCDIR)PlatformSDK\lib\amd64
NOBOR_PATH=/LIBPATH:$(_LIBSDK)
!elif defined(MSSDK)
_LIBSDK=$(MSSDK)lib\x64
NOBOR_PATH=/LIBPATH:$(_LIBSDK)
!endif
!ifdef LINK_NOBOR
LINKOPTS_EXE=/LIBPATH:$(_LIBRTL) $(NOBOR_PATH) $(_LNK_EXE_MAP) $(LNDEBUG)
!else
LINKOPTS_EXE=/L$(_LIBRTL);$(_LIBSDK) $(_LNK_EXE_MAP) $(LNDEBUG)
!endif
LINKOPTS=$(LNOUTDLL) $(LINKOPTS_EXE) $(_LSHOW)
!ifndef LINK_ULINK
_LINKER =$(MSVCDIR)bin\x86_amd64\link.exe               # indirect file linker
_LDAD=_a"/link $(LINKOPTS_EXE) $(CCL_LNK_OPT)"
!else
_LINKER =$(ULINK)                                       # indirect file linker
!endif
LINKER  = $(_LINKER) $(LDFLAGS) $(LNDEBUG) $(_LSHOW)    # default link command
!ifndef LINK_ULINK
CCL     =$(RS)ld $(_LDSW) _v $(_LDAD) _l$(CC) $(CFLAGS) $(_LDFLAGS)  # one-line linker
!else
CCL     =$(RS)ld $(_LDSW) _b _l$(ULINK) $(_ULCCOPT)
!endif
LINKSYS_EXE=                                            # target link system for executable
LINKSYS =                                               # target link system
C_STARTUP=                                              # indirect linker: C startup file
C_LIB   =kernel32.lib                                   # import library
B       =x64.exe                                        # exe file extension
BS      =.exe                                           # host utility extension
MAP     =.map                                           # map file extension
IDP     =.x64                                           # IDP extension
DLLEXT  =64x.wll
IDP     =64.x64                                         # IDP extension
LDR     =64.x64                                         # LDR extension
PLUGIN  =.x64                                           # PLUGIN extension
O       =.obj                                           # object file extension
A       =.lib                                           # library file extension
!if  !$d(NORTL)
IDPSTUB =                                               # STUB file for IDPs
LDRSTUB =                                               # STUB file for LDRs
IDPSLIB =$(C_LIB)                                       # system libraries for IDPs
!else
IDPSTUB =$(LIBDIR)\modstart                             # STUB file for IDPs
LDRSTUB =$(LIBDIR)\modstart                             # STUB file for LDRs
IDPSLIB =$(C_LIB)                                       # system libraries for IDPs
!endif
AR      =$(RS)ar$(BS) _e.at _v _l$(MSVCDIR)bin\x86_amd64\lib.exe $(_LBSHOW) $(AROPT) # librarian
# force C mode for .c files
!if $d(DONT_FORCE_CPP)
FORCEC=/TC
!endif
#############################################################################
!elif $d(__CEARM__)                                     # Visual C++ v4.0 for ARM 4.20
BUILD_ONLY_SERVER=1
COMPILER_NAME=vc
TARGET_PROCESSOR_NAME=arm
CC      ="$(MSVCARMDIR)bin\x86_arm\cl.exe"                 # C++ compiler
CFLAGS  =@$(IDA)$(SYSDIR).cfg $(SWITCH64) $(PROCFLAG) $(NOWARNS) $(_CFLAGS) $(_CSHOW) # default compiler flags
##CFLAG_SUFFIX = /link /subsystem:windowsce
OUTSW   =/Fe                                            # outfile name switch for one-line linker
OBJSW   =/Fo                                            # object file name switch
!ifdef BASE
LDFLAGS =/BASE:$(BASE) $(_LDFLAGS)
!else
LDFLAGS =$(_LDFLAGS)
!endif
OUTDLL  =-LD
LINKOPTS_EXE=/LIBPATH:"$(MSVCARMDIR)lib\armv4" /LIBPATH:"$(ARMSDK)lib\armv4"
LINKOPTS=$(LINKOPTS_EXE) $(_LSHOW)
_LINKER =$(MSVCARMDIR)bin\x86_arm\link.exe                   # indirect file linker
LINKER  =$(_LINKER) $(LDFLAGS) $(LNDEBUG)               # default link command
_LDAD=_a"/link /subsystem:windowsce,4.20 /machine:arm /armpadcode $(CCL_LNK_OPT) /LIBPATH:\"$(MSVCARMDIR)lib\armv4\" /LIBPATH:\"$(ARMSDK)lib\armv4\""
CCL     =$(RS)ld $(_LDSW) _c $(_LDAD) _l$(CC) $(CFLAGS) $(_LDFLAGS) # one-line linker
C_LIB   =corelibc.lib coredll.lib                       # import library
B       =_arm.exe                                       # exe file extension
BS      =.exe                                           # host utility extension
MAP     =.mparm                                         # map file extension
IDP     =.cearm32                                       # IDP extension
DLLEXT  =.dll
IDP     =.cearm32                                       # IDP extension
LDR     =.cearm32                                       # LDR extension
PLUGIN  =.cearm32                                       # PLUGIN extension
O       =.obj                                           # object file extension
A       =.lib                                           # library file extension
IDPSLIB =$(C_LIB)                                       # system libraries for IDPs
_LIBR   =$(MSVCARMDIR)bin\x86_arm\lib.exe
AR      =$(RS)ar$(BS) _e.at _v "_l$(_LIBR)" $(_LBSHOW) $(AROPT) # librarian
# force C mode for .c files
!if $d(DONT_FORCE_CPP)
FORCEC=/TC
!endif
_ARMASM ="$(MSVCARMDIR)bin\x86_arm\armasm.exe"
R32     =$(RS)\x86_win_vc_opt\                          #
B32     =$(BS)
#############################################################################
!elif $d(__VC__)                                        # Visual Studio 2008 for x86
TARGET_PROCESSOR_NAME=x86
COMPILER_NAME=vc
CC      =$(MSVCDIR)bin\cl.exe                           # C++ compiler
CFLAGS  =@$(IDA)$(SYSDIR).cfg $(RUNTIME_LIBSW) $(SWITCH64) $(NOWARNS) $(_CFLAGS) $(_CSHOW) # default compiler flags
!ifndef LINK_ULINK
OUTSW   =/Fe                                            # outfile name switch for one-line linker
OBJSW   =/Fo                                            # object file name switch
BASESW  =/BASE
OUTDLL  =/LD
LNOUTDLL=/DLL
!else
OUTSW   =-ZO
OUJSW   =-j
BASESW  =-b
LNOUTDLL=-Tpd                                           # output is DLL(32) switch
OUTDLL  =-Tpd
!endif
!ifdef BASE
LDFLAGS =$(BASESW):$(BASE) $(_LDFLAGS)
!else
LDFLAGS =$(_LDFLAGS)
!endif
_LIBRTL=$(MSVCDIR)lib
!ifndef VC_WITHOUT_PSDK
_LIBSDK=$(MSVCDIR)PlatformSDK\lib
NOBOR_PATH=/LIBPATH:$(_LIBSDK)
!elif defined(MSSDK)
_LIBSDK=$(MSSDK)lib
NOBOR_PATH=/LIBPATH:$(_LIBSDK)
!endif
!ifdef LINK_NOBOR
LINKOPTS_EXE=/LIBPATH:$(_LIBRTL) $(NOBOR_PATH) $(_LNK_EXE_MAP) $(LNDEBUG) /LARGEADDRESSAWARE /DYNAMICBASE
!else
LINKOPTS_EXE=/L$(_LIBRTL);$(_LIBSDK) $(_LNK_EXE_MAP) $(LNDEBUG)
!endif
LINKOPTS=$(LNOUTDLL) $(LINKOPTS_EXE) $(_LSHOW) $(LNDEBUG)
!ifndef LINK_ULINK
_LINKER =$(MSVCDIR)bin\link.exe                         # indirect file linker
_LDAD=_a"/link $(LINKOPTS_EXE) $(LDFLAGS)"
!else
_LINKER =$(ULINK)                                       # indirect file linker
!endif
LINKER  = $(_LINKER) $(LDFLAGS) $(LNDEBUG) $(_LSHOW)    # default link command
!ifdef LINK_ULINK
CCL     =$(RS)ld $(_LDSW) _b _l$(ULINK) $(_ULCCOPT)
!else
CCL     =$(RS)ld $(_LDSW) _v $(_LDAD) _l$(CC) $(CFLAGS)  # one-line linker
!endif
LINKSYS_EXE=                                            # target link system for executable
LINKSYS =                                               # target link system
C_STARTUP=                                              # indirect linker: C startup file
C_LIB   =kernel32.lib                                   # import library
B       =$(SUFF64).exe                                  # exe file extension
BS      =.exe                                           # host utility extension
MAP     =.map                                           # map file extension
DLLEXT  =$(SUFF64).wll
IDP     =$(SUFF64).w$(ADRSIZE)                          # IDP extension
!ifdef __EA64__
LDR     =64.l$(ADRSIZE)                                 # LDR extension
PLUGIN  =.p$(ADRSIZE)                                   # PLUGIN extension
!else
LDR     =.ldw
PLUGIN  =.plw
!endif
O       =.obj                                           # object file extension
A       =.lib                                           # library file extension
!if  !$d(NORTL)
IDPSTUB =                                               # STUB file for IDPs
LDRSTUB =                                               # STUB file for LDRs
IDPSLIB =$(C_LIB)                                       # system libraries for IDPs
!else
IDPSTUB =$(LIBDIR)\modstart                             # STUB file for IDPs
LDRSTUB =$(LIBDIR)\modstart                             # STUB file for LDRs
IDPSLIB =$(C_LIB)                                       # system libraries for IDPs
!endif
AR      =$(RS)ar$(BS) _e.at _v _l$(MSVCDIR)bin\lib.exe $(_LBSHOW) $(AROPT) # librarian
# force C mode for .c files
!if $d(DONT_FORCE_CPP)
FORCEC=/TC
!endif
#############################################################################
!else                                                   # Borland C++ for NT (WIN32)
TARGET_PROCESSOR_NAME=x86
COMPILER_NAME=bcc
CC      =$(BCB)\bin\bcc32.exe                           # C++ compiler
IMPLIB  =$(BCB)\bin\implib.exe                          # implib executable name
ASM     =$(BC5_COM)\bin\tasm32.exe                      # assembler
!ifdef __PRECOMPILE__
CC_PRECOMPILE= -H
!endif
CFLAGS  =+$(IDA)$(SYSDIR).cfg $(SWITCH64) $(CC_PRECOMPILE) -pr $(NOWARNS) $(_CFLAGS) $(_CSHOW) # default compiler flags
AFLAGS  =/D__FLAT__ /t/ml/m5$(_AFLAGS)                  # default assembler flags
!ifndef LINK_ULINK
OUTSW   =-n -e                                          # outfile name switch for one-line linker
!else
OUTSW   =-ZO                                            # outfile name switch for one-line linker
!endif
OBJSW   =-n. -o                                         # object file switch
OUTDLL  =/Tpd                                           # output is DLL switch
!ifdef BASE
NT_BSW  =-b=$(BASE)
!endif
LDFLAGS =$(NT_BSW) $(_LDFLAGS)
!ifdef LINK_ULINK
_LINKER =$(ULINK)                                       # indirect file linker
!else
_LINKER =$(BCB)\bin\ilink32.exe -Gn                     # indirect file linker
!endif
LINKER  = $(_LINKER) $(LDFLAGS) $(LNDEBUG) $(_LSHOW)    # default link command
LINKSYS_EXE=                                            # target link system for executable
LINKSYS =                                               # target link system
C_STARTUP=c0x32                                         # indirect linker: C startup file
C_IMP   =import32.lib                                   # import library
C_LIB   =$(C_IMP) cw32mt.lib                            # indirect linker: default C library
!ifndef LINK_ULINK
CCL     =$(RS)ld $(_LDSW) _b _l$(CC) $(CFLAGS) $(_LDFLAGS)       # one-line linker
!else
CCL     =$(RS)ld $(_LDSW) _b _a"$(C_LIB)" _l$(ULINK) $(_ULCCOPT) $(C_STARTUP)
!endif
B       =$(SUFF64).exe                                  # exe file extension
BS      =.exe                                           # host utility extension
MAP     =.mpb                                           # map file extension
IDP     =$(SUFF64).w$(ADRSIZE)                          # IDP extension
DLLEXT  =$(SUFF64).wll
!ifdef __EA64__
LDR     =64.l$(ADRSIZE)                                 # LDR extension
PLUGIN  =.p$(ADRSIZE)                                   # PLUGIN extension
!else
LDR     =.ldw
PLUGIN  =.plw
!endif
ORDINALS= #-o                                           # import functions by ordinals
# -c case sensitive
# -C clear state before linking
# -s detailed map of segments
# -m detailed map of publics
# -r verbose
LINKOPTS_EXE= $(_LNK_EXE_MAP) -c -C $(ORDINALS) $(LNDEBUG) -L$(BCB)\lib
LINKOPTS=$(OUTDLL) $(LINKOPTS_EXE) $(_LSHOW)
O       =.obj                                           # object file extension
A       =.lib                                           # library file extension
!if  !$d(NORTL)
IDPSTUB =$(BCB)\lib\c0d32                               # STUB file for IDPs
LDRSTUB =$(BCB)\lib\c0d32                               # STUB file for LDRs
IDPSLIB =$(C_LIB)                                       # system libraries for IDPs
!else
IDPSTUB =$(LIBDIR)\modstart                             # STUB file for IDPs
LDRSTUB =$(LIBDIR)\modstart                             # STUB file for LDRs
IDPSLIB =$(C_IMP)                                       # system libraries for IDPs
!endif
AR      =$(RS)ar$(BS) _a _e.at "_l$(TLIB)" _f/C/E/P128 $(AROPT) # librarian
# force C mode for .c files
!if $d(DONT_FORCE_CPP)
FORCEC=-P-
!endif
!endif
#############################################################################

SYSDIR=$(TARGET_PROCESSOR_NAME)_$(SYSNAME)_$(COMPILER_NAME)_$(ADRSIZE)
LIBDIR=$(IDA)lib\$(SYSDIR)                            # libraries directory
OBJDIR=obj\$(SYSDIR)$(OPTSUF)                         # object files directory

!if 0           # this is for makedep
F=
!else
F=$(OBJDIR)\                        # object files dir with backslash
L=$(LIBDIR)\                        # library files dir with backslash
R=$(IDA)bin\                        # main result directory
!endif

!ifndef R32
R32=$(R)                            # can be defined before for build x64 in win32
B32=$(B)
!else
B32=$(BS)
!endif

HC=$(R32)ihc$(B32)                  # Help Compiler
STM=$(R32)stm$(B32)

IDALIB=$(L)ida$(A)
DUMB=$(L)dumb$(O)
HLIB=$(HI)_ida.hlp

CLPLIB=$(L)clp$(A)
########################################################################
!if !$d(__ANDROID__) && !$d(__ARMLINUX__)
MAKEDEFS=$(MAKEDEFS) -U__MSDOS__ -D__NT__
!endif

!ifdef __EA64__
!ifdef __X64__
MAKEDEFS=$(MAKEDEFS) -D__X64__
!else
MAKEDEFS=$(MAKEDEFS) -D__EA64__
!endif
!endif
!ifdef __VC__
MAKEDEFS=$(MAKEDEFS) -D__VC__
!endif

### for 'if exist DIRECTORY'
!IF "$(OS)" == "Windows_NT"
CHKDIR=
!ELSE
CHKDIR=/nul
!ENDIF

########################################################################
!ifndef CONLY
CONLY=-c
!endif

.cpp$(O):
!if $d(__ANDROID__) || $d(__ARMLINUX__)
	$(CCX) $(CPPFLAGS) $(CONLY) $(OBJSW)$@ $<
.c$(O):
	$(CC) $(CFLAGS) $(CONLY) $(OBJSW)$@ $<
!else
        $(CC) $(CFLAGS) $(CONLY) {$< }
.c$(O):
        $(CC) $(CFLAGS) $(CONLY) $(FORCEC) {$< }
.asm$(O):
        $(ASM) $(AFLAGS) $*,$(F)$*
!endif

.hls.hhp:
        $(HC) -t $(HLIB) -i$@ $?
########################################################################
