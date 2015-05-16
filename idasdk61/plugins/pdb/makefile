PROC=pdb
O1=old
O2=pdbreg
ADDITIONAL_GOALS=cfg
!ifdef __VC__
ADDITIONAL_LIBS=oleaut32.lib ole32.lib
!endif
#__CFLAGS=/wd4191
!include ..\plugin.mak

cfg: $(C)pdb.cfg
$(C)pdb.cfg: pdb.cfg
	$(CP) $? $@

# MAKEDEP dependency list ------------------
$(F)old$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)diskio.hpp    \
	          $(I)err.h $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp            \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
	          $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp bc5_add.h         \
	          cvconst.h dbghelp.h old.cpp oldpdb.h
$(F)pdb$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)compress.hpp  \
	          $(I)dbg.hpp $(I)demangle.hpp $(I)diskio.hpp $(I)err.h     \
	          $(I)fixup.hpp $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp      \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)ieee.h            \
	          $(I)ints.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp  \
	          $(I)loader.hpp $(I)md5.h $(I)nalt.hpp $(I)name.hpp        \
	          $(I)netnode.hpp $(I)offset.hpp $(I)pro.h $(I)queue.hpp    \
	          $(I)segment.hpp $(I)srarea.hpp $(I)struct.hpp             \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp                   \
	          ../../ldr/pe/pe.h ../../ldr/windmp/common.h               \
	          ../../module/idaidp.hpp     \
	          $(I)intel.hpp         \
	          common.cpp cvconst.h dia2.h oldpdb.h pdb.cpp
$(F)pdbreg$(O)  : $(I)llong.hpp $(I)pro.h cvconst.h pdbreg.cpp
