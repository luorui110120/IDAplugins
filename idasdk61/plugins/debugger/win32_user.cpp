/*
This is main source code for the local win32 debugger module
*/
#ifdef __X64__
char wanted_name[] = "Local Win64 debugger";
#else
char wanted_name[] = "Local Win32 debugger";
#endif
#define DEBUGGER_NAME  "win32"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#define DEBUGGER_FLAGS DBG_FLAG_EXITSHOTOK|DBG_FLAG_LOWCNDS|DBG_FLAG_DEBTHREAD
#define HAVE_APPCALL
#define S_FILETYPE     f_PE
#define win32_init_plugin       init_plugin
#define win32_term_plugin       term_plugin

#include <fpro.h>
#include <ua.hpp>
#include <idd.hpp>
#include <area.hpp>
#include <loader.hpp>
#include "win32_debmod.h"

win32_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "win32_local_impl.cpp"
#include "common_local_impl.cpp"

