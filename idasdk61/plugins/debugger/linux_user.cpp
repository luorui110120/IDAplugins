
char wanted_name[] = "Local Linux debugger";
#define DEBUGGER_NAME  "linux"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#define DEBUGGER_FLAGS DBG_FLAG_LOWCNDS | DBG_FLAG_DEBTHREAD
#define HAVE_APPCALL
#define S_FILETYPE     f_ELF

#include <fpro.h>
#include <idd.hpp>
#include <ua.hpp>
#include <area.hpp>
#include <loader.hpp>
#include "linux_debmod.h"

linux_debmod_t g_dbgmod;
bool ignore_sigint = false;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "linux_local_impl.cpp"
#include "common_local_impl.cpp"


