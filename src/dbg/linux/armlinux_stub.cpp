#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Remote ARM Linux/Android debugger";
#define DEBUGGER_NAME  "armlinux"
#define PROCESSOR_NAME "arm"
#define TARGET_PROCESSOR PLFM_ARM
#define DEBUGGER_ID    DEBUGGER_ID_ARM_LINUX_USER
#define DEBUGGER_FLAGS (DBG_FLAG_REMOTE      \
                      | DBG_FLAG_SMALLBLKS   \
                      | DBG_FLAG_LOWCNDS     \
                      | DBG_FLAG_DEBTHREAD   \
                      | DBG_FLAG_PREFER_SWBPTS)

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <dbg.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <segregs.hpp>
#include <network.hpp>
#include "dbg_plugmod.hpp"
#include "deb_arm.hpp"

#include "dbg_rpc_client.h"
#include "rpc_debmod.h"
#include "stack_unwind.hpp"
#undef HAVE_UPDATE_CALL_STACK   // not implemented for ARM

#include "common_stub_impl.cpp"
#include "linux_local_impl.cpp"

//--------------------------------------------------------------------------
// HT_DBG listener
DECLARE_LISTENER(dbg_listener_t, dbg_plugmod_t, pm);//lint !e754 'pm' not referenced

//--------------------------------------------------------------------------
struct dbg_plugmod_t : public dbg_plugmod_stub_t
{
  easet_t pending_addresses;  //lint !e754 local not referenced

  dbg_plugmod_t()
  {
    debugger.filetype = f_ELF;
  }
  virtual ~dbg_plugmod_t() override;

#define DEFAULT_PLATFORM_NAME "linux"
  rpc_debmod_t g_dbgmod = rpc_debmod_t(DEFAULT_PLATFORM_NAME);
  virtual debmod_t &get_debmod() override { return g_dbgmod; }

  dbg_listener_t dbg_listener = dbg_listener_t(*this);

  //--------------------------------------------------------------------------
  bool init_plugin()
  {
    bool ok = init_linux_plugin(&debugger);
    if ( ok )
    {
      hook_event_listener(HT_DBG, &dbg_listener);
      debugger.flags |= DBG_HAS_OPEN_FILE;
      debugger.flags |= DBG_HAS_APPCALL;
      // typically arm has no single step mechanism, arm64 macOS11 is an exception.
      debugger.flags &= ~DBG_HAS_SET_RESUME_MODE;
    }
    return ok;
  }
  void term_plugin() {}

  //--------------------------------------------------------------------------
  // For ARM, we have to set the low bit of the address to 1 for thumb mode
  drc_t g_dbgmod_update_bpts(
          int *nbpts,
          update_bpt_info_t *bpts,
          int nadd,
          int ndel,
          qstring *errbuf) override
  {
    // This function is called from debthread, but to use get_sreg() we must
    // switch to the mainthread
    struct ida_local arm_bptea_fixer_t : public exec_request_t
    {
      update_bpt_info_t *bpts;
      update_bpt_info_t *e;
      qvector<ea_t *> thumb_mode;
      virtual ssize_t idaapi execute(void) override
      {
        for ( update_bpt_info_t *b=bpts; b != e; b++ )
        {
          if ( b->type == BPT_SOFT && get_sreg(b->ea, ARM_T) == 1 )
          {
            b->ea++; // odd address means that thumb bpt must be set
            thumb_mode.push_back(&b->ea);
          }
        }
        return 0;
      }
      arm_bptea_fixer_t(update_bpt_info_t *p1, update_bpt_info_t *p2)
        : bpts(p1), e(p2) {}
    };
    arm_bptea_fixer_t abf(bpts, bpts+nadd);
    execute_sync(abf, MFF_READ);

    drc_t drc = g_dbgmod.dbg_update_bpts(nbpts, bpts, nadd, ndel, errbuf);

    // reset the odd bit because the addresses are required by the caller
    for ( int i=0; i < abf.thumb_mode.size(); i++ )
      (*abf.thumb_mode[i])--;

    return drc;
  }
};
#include "arm_local_impl.cpp"
#include "common_local_impl.cpp"
