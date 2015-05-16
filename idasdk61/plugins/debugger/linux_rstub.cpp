#define REMOTE_DEBUGGER
#define RPC_CLIENT

char wanted_name[] = "Remote Linux debugger";
#define DEBUGGER_NAME  "linux"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE | DBG_FLAG_LOWCNDS | DBG_FLAG_DEBTHREAD
#define HAVE_APPCALL
#define S_FILETYPE     f_ELF

//////
#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <area.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "rpc_client.h"
#include "rpc_debmod.h"
#include "tcpip.h"

rpc_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "linux_local_impl.cpp"
#include "common_local_impl.cpp"
