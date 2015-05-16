PROC=m7900
DESCRIPTION=Mitsubishi series:m7900
ADDITIONAL_GOALS=config

!include ..\module.mak

config: $(C)m7900.cfg

$(C)m7900.cfg: m7900.cfg
	$(CP) $? $@


# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)queue.hpp $(I)segment.hpp $(I)srarea.hpp $(I)ua.hpp   \
	          $(I)xref.hpp ../idaidp.hpp 7900.hpp ana.cpp ins.hpp
$(F)emu$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ints.hpp        \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          7900.hpp emu.cpp ins.hpp
$(F)ins$(O)     : $(I)area.hpp $(I)bytes.hpp $(I)fpro.h $(I)funcs.hpp       \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h      \
	          $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp ins.cpp ins.hpp
$(F)out$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)ints.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp  \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          7900.hpp ins.hpp out.cpp
$(F)reg$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          ../iocommon.cpp 7900.hpp ins.hpp reg.cpp
