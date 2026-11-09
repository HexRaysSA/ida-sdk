/*
This is main source code for the local win32 debugger module
*/

static const char wanted_name[] = "Local Windows debugger";

#define DEBUGGER_NAME  "win32"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#define DEBUGGER_FLAGS (DBG_FLAG_EXITSHOTOK   \
                      | DBG_FLAG_LOWCNDS      \
                      | DBG_FLAG_DEBTHREAD    \
                      | DBG_FLAG_ANYSIZE_HWBPT\
                      | DBG_FLAG_ADD_ENVS     \
                      | DBG_FLAG_MERGE_ENVS)
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)

#define HAVE_APPCALL
#define S_FILETYPE     f_PE

// We must rename those method because common files
// refer to them as init_plugin/term_plugin
// Some other debugger modules compatible with win32
// have their own init/term and still call win32_init/term
// (since no renaming takes place)
#define win32_init_plugin       init_plugin
#define win32_term_plugin       term_plugin

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objidl.h>

#include <fpro.h>
#include <ua.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include "win32_debmod.h"
#include "w32sehch.h"

win32_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "win32_local_impl.cpp"
#include "common_local_impl.cpp"

#include "win32_server_stub.cpp"
