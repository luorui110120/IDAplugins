/*
This is the MAC user land local debugger entry point file
It declares a MAC debugger module and uses the common plugin functions to build the debugger
*/

char wanted_name[] = "Local Mac OS X debugger";
#define DEBUGGER_NAME  "macosx"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_MACOSX_USER
#define DEBUGGER_FLAGS DBG_FLAG_LOWCNDS | DBG_FLAG_DEBTHREAD
#define HAVE_APPCALL
#define S_FILETYPE     f_MACHO

#include <pro.h>
#include <idd.hpp>
#include <ua.hpp>
#include <area.hpp>
#include <loader.hpp>
#include "mac_debmod.h"

mac_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "mac_local_impl.cpp"
#include "common_local_impl.cpp"

