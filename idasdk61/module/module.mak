_CFLAGS=$(__CFLAGS) -D__IDP__

BASE=0x13000000
__IDP__=1
!include ../../allmake.mak

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

!ifdef H1
HELPS=$(H1)$(HH)
!endif

OBJS=$(F)ins$(O) $(F)ana$(O) $(F)out$(O) $(F)reg$(O) $(F)emu$(O) \
     $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5) $(OBJ6) $(OBJ7) \
     $(OBJ8) $(OBJ9) $(ADDITIONAL_FILES)

IDP_MODULE=$(R)procs\$(PROC)$(IDP)

!ifndef __X64__
DEFFILE=..\idp.def
!else
DEFFILE=..\idp64.def
!endif

all:    objdir $(HELPS) $(IDP_MODULE) $(ADDITIONAL_GOALS)

$(IDP_MODULE): $(OBJS) $(IDALIB) $(DEFFILE)
!ifdef LINK_NOBOR
	$(LINKER) $(LINKOPTS) /STUB:..\stub /OUT:$@ $(OBJS) $(IDALIB) user32.lib
        -@$(RM) $(@R).exp
        -@$(RM) $(@R).lib
!else
        $(LINKER) @&&~
$(LINKOPTS) $(IDPSTUB) $(OBJS)
$@

$(IDALIB) $(IDPSLIB)
$(DEFFILE)
~
!ifndef __X64__
        $(PEUTIL) -d$(DEFFILE) $@
!endif
!endif
!ifdef DESCRIPTION
        $(RS)mkidp$(BS) $@ "$(DESCRIPTION)"
!endif

!include ../../objdir.mak

!ifndef __VC__
xml: $(C)$(PROC).xml
$(C)$(PROC).xml: $(PROC).xml
	$(CP) $? $@
!else
xml:
	@echo
!endif
