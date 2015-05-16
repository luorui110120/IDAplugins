PROC=pilot
ADDITIONAL_GOALS=inc
!include ..\loader.mak

.PHONY: inc
inc: $(RI)pilot.idc
$(RI)pilot.idc:	pilot.idc
	$(CP) $? $@

# MAKEDEP dependency list ------------------
$(F)pilot$(O)   : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)entry.hpp $(I)expr.hpp $(I)fixup.hpp $(I)fpro.h       \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)segment.hpp $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp    \
	          ../idaldr.h common.cpp pilot.cpp pilot.hpp
