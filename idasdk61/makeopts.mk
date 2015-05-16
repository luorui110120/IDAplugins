!if !$d(__ANDROID__) && !$d(__ARMLINUX__)
  __NT__=1
!endif

NO_ULINK=1
SHOW=1
!ifndef NDEBUG
DEBUG=1
!endif

!ifdef DEBCUR
#USE_OPT_LIBS=1
DEBUG=1
!endif

#MAKEPROG=E:\TOOLSES\make.exe

!ifndef VC_USE_CPUS
VC_USE_CPUS=4
!endif

!ifdef NDEBUG
DONT_BUILD_TOOLS=1
!endif

#--------------------------- Compile modes (make options) ----------
!ifndef DEBUG
NDEBUG=1
#ALTBIN=\release
!else
MAKEDEFS=$(MAKEDEFS) -DDEBUG
#ALTBIN=\debug
!endif

!ifndef NO_ULINK
LINK_ULINK = 1
!else
MAKEDEFS=$(MAKEDEFS) -DNO_ULINK
!endif

!ifndef SHOW
NOSHOW=1
!else
MAKEDEFS=$(MAKEDEFS) -DSHOW
!endif

!ifdef MKLIB
MAKEDEFS=$(MAKEDEFS) -DMKLIB
!endif

# for ui\gui-subprojects
!ifdef __EA64__
MAKEDEFS=$(MAKEDEFS) -D__EA64__
!endif
!ifdef __X64__
MAKEDEFS=$(MAKEDEFS) -D__X64__
!endif

# for clp
!ifdef __NT__
MAKEDEFS=$(MAKEDEFS) -D__NT__
!endif

!ifdef __CEARM__
MAKEDEFS=$(MAKEDEFS) -D__CEARM__
!endif

!ifdef __VC__
MAKEDEFS=$(MAKEDEFS) -D__VC__
!endif

#-------------------------------------------------------
!ifndef MAKEPROG
MAKE=$(MAKEDIR)\make.exe $(MAKEDEFS)
!else
MAKE=$(MAKEPROG) $(MAKEDEFS)
!endif

################################EOF###############################
