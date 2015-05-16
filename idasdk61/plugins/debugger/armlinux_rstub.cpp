#define REMOTE_DEBUGGER
#define RPC_CLIENT

char wanted_name[] = "Remote ARM Linux/Android debugger";
#define DEBUGGER_NAME  "armlinux"
#define PROCESSOR_NAME "arm"
#define TARGET_PROCESSOR PLFM_ARM
#define DEBUGGER_ID    DEBUGGER_ID_ARM_LINUX_USER
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE      \
                     | DBG_FLAG_SMALLBLKS   \
                     | DBG_FLAG_LOWCNDS     \
                     | DBG_FLAG_DEBTHREAD
#define HAVE_APPCALL
#define S_FILETYPE     f_ELF

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

#include "arm_local_impl.cpp"
#include "linux_local_impl.cpp"
#include "common_local_impl.cpp"
