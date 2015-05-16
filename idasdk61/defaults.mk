VC_WITHOUT_PSDK=1

#--------------------------- Compiling parts ---------------------
NO_WINFW_REBUILD=1

#INFO_INT_ONLY=1
#SET_NLSPATH=E:\IDA

#IFACE_TXT_ONLY=1
#IFACE_NO_CMD=1

#ADDITIONAL_PLUGINS=loadmap
#ADDITIONAL_LOADERS=bladox
#ADDITIONAL_MODULES=

DEVKEY_TO_BIN=1		# copy development ida.key to Bin directory

#USE_CMD_ECHO=1

#-------------------------------------------------------------------
!ifndef IDA
!error "IDA must be defined!"
!endif

#--------------------------- IDA's paths rules ---------------------
RS=$(IDA)bin\			# host utilities directory. must be used together with BS
#RS=$(IDA)bin\tool\		# host utilities directory

RT=$(R)				# target utilities directory
#RT=$(RS)			# target utilities directory

#RT_NE_R=1			# must defined when $(RT)!=$(R) for unix
#RS_NE_R=1			# must defined when $(RS)!=$(R) for unix

TOOLDIR=$(RS)			# This directory MUST be in path
#TOOLDIR=E:\TOOLSES\		# This directory MUST be in path

PEUTIL=$(TOOLDIR)peutil.exe

ULNK_BASE=$(TOOLDIR)ulink.exe

!ifndef MAKEPROG
MAKEPROG=make.exe
MAKE=$(MAKEPROG) $(MAKEDEFS)
!endif


#BC5_COM=E:\B_COMMON\		# other borland tools

TLIB=$(RS)tlib.exe
#TLIB=$(BC5_COM)bin\tlib.exe

#TVSRC=

ULNK_CFG_DIR=$(RS)

NASM=$(RS)nasmw.exe	        # netwide assembler used for debugger\bochs

!ifndef MKLIB
NOIMPLIB=1			#do not rebuild ida.lib when build dll
!endif
#-------------------------------------------------------
RM=del                                          # File Remover
CP=cp -f
MV=mv
MKDIR=-@mkdir

#--------------------------- Main path'es end variables ---------------------
!ifndef BCB
BCB=c:\progra~2\borland\cbuild~1
#BCB=E:\BCB6\
##INCLUDE_DINKUMWARE=1
!endif

################################
!ifndef MSSDK
MSSDK=C:\PROGRA~1\MICROS~3\WINDOWS\v6.0A\	# mssdk
#MSSDK=J:\_MS\SDK\				# mssdk
!endif

!ifndef VSPATH8
VSPATH8=C:\PROGRA~2\MICROS~1.0\     	# vs2008
!endif
!ifndef VSPATH
VSPATH=C:\PROGRA~2\MICROS~2.0\     	# vs2010
!endif

!ifndef MSVCDIR
MSVCDIR=$(VSPATH)VC\			# for AMD64/clp
!endif

!ifndef MSVCARMDIR
MSVCARMDIR=$(VSPATH8)VC\ce\		# for __CEARM__
!endif

!ifndef ARMSDK
ARMSDK=$(VSPATH8)SmartDevices\SDK\PocketPC2003\	# path to arm sdk
!endif

!ifndef GCCBINDIR
GCCBINDIR=c:\cygwin\bin			# for mkapi
#GCCBINDIR=E:\mingw\bin			# for mkapi
!endif

!ifndef PYTHON_ROOT
PYTHON_ROOT=c:
#PYTHON_ROOT=j:/DEVTOOL
!endif

!ifndef PYTHON
PYTHON=$(PYTHON_ROOT)/python26/python.exe
!endif

!ifndef SWIG
SWIG=swig
#SWIG=J:\DEVTOOL\Swig-1.3.40\swig.exe
!endif

!ifndef QT_ROOT
QT_ROOT=c:
#QT_ROOT=J:\DEVTOOL
!endif
QTDIR=$(QT_ROOT)\Qt\4.7.2\      # with backslash

!ifndef ANDROID_NDK
  ANDROID_NDK=c:\android-ndk-r4b\ # with backslash
!endif

!ifndef SOURCERY
  SOURCERY=C:\CODESO~1\SOURCE~1  # C:\CodeSourcery\Sourcery G++ Lite\
!endif

!ifndef STLDIR
  STLDIR=z:\idasrc\third_party\stlport
!endif

!ifndef DEBUG
#NDEBUG=1
!endif


################################EOF###############################
