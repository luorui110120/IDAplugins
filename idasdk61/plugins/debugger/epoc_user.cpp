/*
        This is the Symbian (EPOC) user land debugger entry point file
*/

#include <windows.h>

#define REMOTE_DEBUGGER

char wanted_name[] = "Remote Symbian debugger";
#define DEBUGGER_NAME  "epoc"
#define PROCESSOR_NAME "arm"
#define TARGET_PROCESSOR PLFM_ARM
#define DEBUGGER_ID    DEBUGGER_ID_ARM_EPOC_USER
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE       \
                     | DBG_FLAG_FAKE_ATTACH  \
                     | DBG_FLAG_NOHOST       \
                     | DBG_FLAG_NEEDPORT     \
                     | DBG_FLAG_CAN_CONT_BPT \
                     | DBG_FLAG_NOSTARTDIR   \
                     | DBG_FLAG_NOPASSWORD   \
                     | DBG_FLAG_MANMEMINFO

// Tried to activate appcall but failed: metrotrk refuses to write to R13
//#define HAVE_APPCALL

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <err.h>
#include <ua.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <segment.hpp>
#include "epoc_debmod.h"

epoc_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "arm_local_impl.cpp"
#include "epoc_local_impl.cpp"
#include "common_local_impl.cpp"

