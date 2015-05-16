PROC=h8
DESCRIPTION=Hitachi H8:h8300:h8300a:h8s300:h8s300a
ADDITIONAL_GOALS=config

!include ..\module.mak

config:    $(C)h8.cfg
$(C)h8.cfg:  h8.cfg
	$(CP) $? $@

# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)queue.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
	          ../idaidp.hpp ana.cpp h8.hpp ins.hpp
$(F)emu$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)frame.hpp $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp       \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp emu.cpp h8.hpp      \
	          ins.hpp
$(F)ins$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)queue.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
	          ../idaidp.hpp h8.hpp ins.cpp ins.hpp
$(F)out$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)queue.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
	          ../idaidp.hpp h8.hpp ins.hpp out.cpp
$(F)reg$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp h8.hpp ins.hpp      \
	          reg.cpp
