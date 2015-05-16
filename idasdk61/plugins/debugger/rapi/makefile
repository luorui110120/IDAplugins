
!include ../../../allmake.mak

!ifdef __CEARM__
all:    objdir rapi_arm.dll
!else
all:    objdir rapitest.exe
!endif

run:
        rapitest.exe

rapi_arm.dll: $(F)rapi_arm$(O)
        $(CCL) /LD $(OUTSW)$@ $(F)rapi_arm$(O) $(DUMB) $(L)pro$(A) $(C_LIB) $(ARM_RTTI_LIB)

rapitest.exe: $(F)rapitest$(O) ..\async.cpp $(L)pro$(A) $(DUMB)
        $(CCL) $(OUTSW)$@ $(F)rapitest$(O) $(L)pro$(A) $(DUMB)

!include ../../../objdir.mak

# MAKEDEP dependency list ------------------
$(F)rapi_arm$(O): $(I)auto.hpp $(I)diskio.hpp $(I)err.h $(I)fpro.h          \
	          $(I)ida.hpp $(I)kernwin.hpp $(I)llong.hpp $(I)pro.h       \
	          ../async.cpp ../async.h ../consts.h rapi.h rapi_arm.cpp
$(F)rapitest$(O): $(I)auto.hpp $(I)diskio.hpp $(I)err.h $(I)fpro.h          \
	          $(I)ida.hpp $(I)kernwin.hpp $(I)llong.hpp $(I)pro.h       \
	          ../async.cpp ../async.h ../consts.h rapi.h rapitest.cpp
