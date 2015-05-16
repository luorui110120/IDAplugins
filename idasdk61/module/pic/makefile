PROC=pic
DESCRIPTION=Microchip PIC:PIC12Cxx:PIC16Cxx:PIC18Cxx
ADDITIONAL_GOALS=config

!include ..\module.mak

config: $(C)pic12.cfg $(C)pic14.cfg $(C)pic16.cfg
$(C)pic12.cfg:  pic12.cfg
	$(CP) $? $@
$(C)pic14.cfg:  pic14.cfg
	$(CP) $? $@
$(C)pic16.cfg:  pic16.cfg
	$(CP) $? $@

# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          ana.cpp ins.hpp pic.hpp
$(F)emu$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp $(I)ida.hpp        \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          emu.cpp ins.hpp pic.hpp
$(F)ins$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ins.cpp ins.hpp     \
	          pic.hpp
$(F)out$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp $(I)ida.hpp        \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)struct.hpp $(I)ua.hpp $(I)xref.hpp     \
	          ../idaidp.hpp ins.hpp out.cpp pic.hpp
$(F)reg$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          ../iocommon.cpp ins.hpp pic.hpp reg.cpp
