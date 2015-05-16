PROC=uunp
O1=resext
O2=win9x
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)resext$(O)  : $(I)area.hpp $(I)bytes.hpp $(I)fpro.h $(I)funcs.hpp       \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h      \
	          $(I)prodir.h $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp      \
	          resext.cpp uunp.hpp
$(F)uunp$(O)    : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)dbg.hpp       \
	          $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp uunp.cpp uunp.hpp
$(F)win9x$(O)   : $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)fpro.h         \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp uunp.hpp win9x.cpp
