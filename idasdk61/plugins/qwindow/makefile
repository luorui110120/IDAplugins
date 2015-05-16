# under ms windows this plugin can be built only with visual studio
!ifdef __VC__
!ifndef __X64__
BUILD_QWINDOW=1
!endif
!endif

# under unix, build 32-bit version of this plugin
!ifndef __NT__
!ifndef __X64__
BUILD_QWINDOW=1
!endif
!endif

!ifdef BUILD_QWINDOW
PROC=qwindow
__CFLAGS=-I"$(QTDIR)include\QtCore" \
         -I"$(QTDIR)include\QtGui"  \
         -I"$(QTDIR)include\QtXml"  \
         -I"$(QTDIR)include"        \
         -I.                        \
         -DUNICODE                  \
         -DQT_DLL                   \
         -DQT_XML_LIB               \
         -DQT_GUI_LIB               \
         -DQT_CORE_LIB              \
         -DQT_NAMESPACE=QT          \
         -DQT_THREAD_SUPPORT

!ifdef __MAC__
PREF=$(QTDIR)lib/
ADDITIONAL_LIBS="$(PREF)QtXml.framework/QtXml"  \
                "$(PREF)QtGui.framework/QtGui"  \
                "$(PREF)QtCore.framework/QtCore"
!else
!ifdef __LINUX__
PREF=$(QTDIR)lib/lib
POST=.so
!endif
!ifdef __NT__
PREF=$(QTDIR)lib\ # with backslash
!ifdef NDEBUG
POST=4$(A)
!else
POST=d4$(A)
!endif
!endif
ADDITIONAL_LIBS="$(PREF)QtXml$(POST)"  \
                "$(PREF)QtGui$(POST)"  \
                "$(PREF)QtCore$(POST)"
!endif
O1=moc_myactions

!include ..\plugin.mak

$(F)moc_myactions$(O): myactions.h #| $(OBJDIR)
	$(QTDIR)bin\moc -I. myactions.h >$(F)moc_myactions.cpp
	$(CC) $(CFLAGS) -c $(OBJSW)$@ $(F)moc_myactions.cpp

# MAKEDEP dependency list ------------------
$(F)qwindow$(O) : $(I)area.hpp $(I)bytes.hpp $(I)fpro.h $(I)funcs.hpp       \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp                 \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp qwindow.cpp
!else
!ifndef __NT__
all:
!endif
!endif