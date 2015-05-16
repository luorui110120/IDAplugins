#
#           Common part of Visual C++ Makefiles for IDA.
#
#--------------------------- Main IDA directory   --------------------------
!ifndef IDA
!error Please set IDA variable! (with a trailing backslash!)
!endif

############################################################################
#                            From ALLMAKE.MAK                              #
############################################################################
# include and help directories are common for all platforms and compilers:
I=$(IDA)include\\
L=$(IDA)lib\vc.w32\                  # libraries directory
R=$(IDA)bin\                         # results directory
F=.\vc.w32\                          # object files directory
SUBDIR=plugins\\
PLUGIN=.plw                          # PLUGIN extension
O=.obj                               # object file extension
A=.lib                               # library file extension
RM=erase /q                          # File Remover
IDALIB=$(L)ida$(A)

############################################################################
#                            From PLUGIN.MAK                               #
############################################################################
!ifdef O1
OBJ1=$(F)$(O1)$(O)
!endif

!ifdef O2
OBJ2=$(F)$(O2)$(O)
!endif

!ifdef O3
OBJ3=$(F)$(O3)$(O)
!endif

!ifdef O4
OBJ4=$(F)$(O4)$(O)
!endif

!ifdef O5
OBJ5=$(F)$(O5)$(O)
!endif

!ifdef O6
OBJ6=$(F)$(O6)$(O)
!endif

!ifdef O7
OBJ7=$(F)$(O7)$(O)
!endif

!ifdef O8
OBJ8=$(F)$(O8)$(O)
!endif

!ifdef O9
OBJ9=$(F)$(O9)$(O)
!endif

!ifdef O10
OBJ10=$(F)$(O10)$(O)
!endif

!ifdef O11
OBJ11=$(F)$(O11)$(O)
!endif

!ifdef O12
OBJ12=$(F)$(O12)$(O)
!endif

!ifdef O13
OBJ13=$(F)$(O13)$(O)
!endif

!ifdef O14
OBJ14=$(F)$(O14)$(O)
!endif

!ifdef O15
OBJ15=$(F)$(O15)$(O)
!endif

OBJS=$(F)$(PROC)$(O) $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5) $(OBJ6) $(OBJ7) \
     $(OBJ8) $(OBJ9) $(OBJ10) $(OBJ11) $(OBJ12) $(OBJ13) $(OBJ14) $(OBJ15)

BINARY=$(R)$(SUBDIR)$(PROC)$(PLUGIN)

############################################################################
#                    From Visual Studio exported MAKEFILE                  #
############################################################################
all: $(F) "$(BINARY)"

clean:
	-@$(RM) $(F)*$(O)
	-@$(RM) $(F)*$(A)
	-@$(RM) $(F)*.exp
	-@$(RM) "$(BINARY)"

distclean: clean
	-@$(RM) $(F)*
	rmdir $(F)

$(F):
	if not exist $(F) mkdir $(F)

CPP=cl.exe
CPP_PROJ=/nologo /GX /I "$(I)" /D "WIN32" /D "_USRDLL" /D "__NT__" /D "__IDP__" /D MAXSTR=1024 /Fo$(F) /c

.c{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $<
<<

.cpp{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $<
<<

LINK32=link.exe
LINK32_FLAGS="$(IDALIB)" $(LIBS) /nologo /dll /out:"$(BINARY)" /implib:$(F)$(PROC)$(A) /libpath:"$(L)" /export:PLUGIN

"$(BINARY)" : $(F) $(OBJS)
	$(LINK32) @<<
  $(LINK32_FLAGS) $(OBJS)
<<
