!ifndef __NT__
__BUG=1
!endif
!ifdef __X64__
!undef __BUG
__BUG=1
!endif
!ifdef __VC__
!undef __BUG
__BUG=1
!endif
!ifdef __BUG
All:
  @echo This plugin can be compiled only with Borland C++Builder
!else

PROC=chart
O1=chartbox
DONT_BUILD_PLUGIN=1
BINARY=$(BIN_PATH)$(PROC)$(PLUGIN)

__CFLAGS=/I$(BCB)\include\vcl -H=$(F)vcl.csm -Hc -Vx -Ve -WD -X- -b- -tWM -a8 -w-8057 -DNO_STRICT
_LDFLAGS=/L$(BCB)\lib\obj -aa -Gn
_VCLIBS=vcle.lib rtl.lib vcl.lib tee.lib cp32mt.lib import32.lib

!include ..\plugin.mak

$(BINARY): $(DEFFILE) $(OBJS) $(IDALIB)
	$(LINKER) @&&~
$(LINKOPTS) $(LDRSTUB) $(BCB)\lib\obj\sysinit.obj $(OBJS)
$@

$(IDALIB) $(_VCLIBS)
$(DEFFILE)
~
        $(PEUTIL) -d$(DEFFILE) $@
!endif

# MAKEDEP dependency list ------------------
$(F)chart$(O)   : chart.cpp
$(F)chartbox$(O): $(I)area.hpp $(I)bytes.hpp $(I)expr.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp chartbox.cpp chartbox.h
