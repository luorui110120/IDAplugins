_CFLAGS=$(__CFLAGS) -D__IDP__ -D__PLUGIN__

__IDP__=1
!ifndef O
!include ../../allmake.mak
!endif

!ifdef BETA
F=beta$(F)
!endif

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

!ifdef H1
HELPS=$(H1)$(HH)
!endif

OBJS=$(F)$(PROC)$(O) $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5) $(OBJ6) $(OBJ7) \
     $(OBJ8) $(OBJ9) $(OBJ10) $(OBJ11) $(OBJ12) $(OBJ13) $(OBJ14) $(OBJ15)   \
     $(ADDITIONAL_OBJS)

BIN_PATH=$(R)plugins\\

!ifndef DONT_BUILD_PLUGIN
BINARY=$(BIN_PATH)$(PROC)$(PLUGIN)
!endif

!ifdef __X64__
DEFFILE=..\plugin64.def
!else
DEFFILE=..\plugin.def
!endif

all:	objdir $(HELPS) $(BINARY) $(ADDITIONAL_GOALS)

clean:
	-@$(RM) $(F)*$(O)
	-@$(RM) $(F)*$(A)
	-@$(RM) $(BINARY)

distclean: clean
	rmdir $(F)

!ifdef __VC__
!ifndef NDEBUG
PDBSW=/PDB:$(BIN_PATH)$(PROC)$(SUFF64).pdb
!endif
!endif

!ifndef DONT_BUILD_PLUGIN
$(BINARY): $(DEFFILE) $(OBJS) $(IDALIB) $(RESFILES)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /OUT:$@ $(PDBSW) $(OBJS) $(IDALIB) user32.lib $(ADDITIONAL_LIBS)
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(OBJS)
$@

$(IDALIB) $(ADDITIONAL_LIBS) $(IDPSLIB)
$(DEFFILE)
$(RESFILES)
~
!ifndef __X64__
        $(PEUTIL) -d$(DEFFILE) $@
!endif
!endif
!endif

!include ../../objdir.mak
