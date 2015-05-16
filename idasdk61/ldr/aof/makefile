PROC=aof
!include ..\loader.mak

unlib$(B): $(F)unlib$(O)
	$(CCL) $(OUTSW)$@ $(F)unlib$(O) $(L)pro$(A)

# MAKEDEP dependency list ------------------
$(F)aof$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)entry.hpp $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp      \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)offset.hpp $(I)pro.h $(I)segment.hpp  \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaldr.h        \
	          aof.cpp aof.h
$(F)unlib$(O)   : $(I)fpro.h $(I)llong.hpp $(I)pro.h aof.h unlib.cpp
