#ifndef __WIN32_DEBUGGER_MODULE__
#define __WIN32_DEBUGGER_MODULE__

#include <windows.h>
#include <Tlhelp32.h>
#include "../../ldr/pe/pe.h"
#include "winbase_debmod.h"

//-V::720 It is advised to utilize the 'SuspendThread' function only when developing a debugger

// Type definitions

class win32_debmod_t;

//--------------------------------------------------------------------------
// image information
struct image_info_t
{
  image_info_t() { memset(this, 0, sizeof(*this)); }
  image_info_t(win32_debmod_t *);
  image_info_t(win32_debmod_t *, ea_t _base, uint32 _imagesize, const qstring &_name);
  image_info_t(win32_debmod_t *, const LOAD_DLL_DEBUG_INFO &i, uint32 _imagesize, const char *_name);
  image_info_t(win32_debmod_t *, const modinfo_t &m);

  win32_debmod_t *sess;
  ea_t base;
  uval_t imagesize;
  qstring name;
  LOAD_DLL_DEBUG_INFO dll_info;
};

// key: image base address
typedef std::map<ea_t, image_info_t> images_t;

//-------------------------------------------------------------------------
struct context_holder_t
{
  bytevec_t buffer;
  PCONTEXT ptr = nullptr;
};

//-------------------------------------------------------------------------
struct context_helper_t
{
  typedef DWORD64 (WINAPI *PGETENABLEDXSTATEFEATURES)();
  PGETENABLEDXSTATEFEATURES pfnGetEnabledXStateFeatures;

  typedef BOOL (WINAPI *PINITIALIZECONTEXT)(PVOID Buffer, DWORD ContextFlags, PCONTEXT *Context, PDWORD ContextLength);
  PINITIALIZECONTEXT pfnInitializeContext;

  typedef BOOL (WINAPI *PGETXSTATEFEATURESMASK)(PCONTEXT Context, PDWORD64 FeatureMask);
  PGETXSTATEFEATURESMASK pfnGetXStateFeaturesMask;

  typedef PVOID (WINAPI *LOCATEXSTATEFEATURE)(PCONTEXT Context, DWORD FeatureId, PDWORD Length);
  LOCATEXSTATEFEATURE pfnLocateXStateFeature;

  typedef BOOL (WINAPI *SETXSTATEFEATURESMASK)(PCONTEXT Context, DWORD64 FeatureMask);
  SETXSTATEFEATURESMASK pfnSetXStateFeaturesMask;

  typedef BOOL (WINAPI *COPYCONTEXT)(PCONTEXT Destination, DWORD ContextFlags, PCONTEXT Source);
  COPYCONTEXT pfnCopyContext;

  int xstate_context_size;
  bool get_xstate_context_size(int *out_ctxsz);
  context_helper_t() { clear(); }
  bool create_context(context_holder_t *out, int *ctxflags);
  bool xstate_helpers_loaded() const { return xstate_context_size > 0; }
  void clear();
};

//--------------------------------------------------------------------------
// thread information
struct thread_info_t : public CREATE_THREAD_DEBUG_INFO
{
  thread_info_t(
          win32_debmod_t *dm,
          const CREATE_THREAD_DEBUG_INFO &i,
          thid_t t,
          wow64_state_t wow64_state);
  win32_debmod_t *debmod;
  thid_t tid;                   // thread id
  int suspend_count;
  ea_t bpt_ea;
  int flags;
#define THR_TRACING 0x0001      // expecting a STEP event
#define THR_WOW64   0x0002      // is wow64 process?
#define THR_NEWNAME 0x0004      // thread was renamed
  ea_t callgate_ea;
  qstring name;

  bool read_context(context_holder_t *out, int clsmask);
  bool write_context(int clsmask, CONTEXT &ctx);
  bool toggle_tbit(bool set_tbit);
  bool is_tracing(void) const { return (flags & THR_TRACING) != 0; }
  bool is_wow64(void) const { return (flags & THR_WOW64) != 0; }
  void set_tracing(void) { flags |= THR_TRACING; }
  void clr_tracing(void) { flags &= ~THR_TRACING; }
  bool is_new_name(void) const { return (flags & THR_NEWNAME) != 0; }
  void clr_new_name(void) { flags &= ~THR_NEWNAME; }
  void set_new_name(void) { flags |= THR_NEWNAME; }
};

//--------------------------------------------------------------------------
inline thread_info_t::thread_info_t(
        win32_debmod_t *dm,
        const CREATE_THREAD_DEBUG_INFO &i,
        thid_t t,
        wow64_state_t wow64_state)
    : CREATE_THREAD_DEBUG_INFO(i), tid(t), suspend_count(0), bpt_ea(BADADDR),
      debmod(dm),
      flags(wow64_state > 0 ? THR_WOW64 : 0),
      callgate_ea(0)
{
}

//--------------------------------------------------------------------------
// Check if the context structure has valid values at the specified portion
// portion is a conbination of CONTEXT_... bitmasks
inline bool has_portion(const CONTEXT &ctx, int portion)
{
  return (ctx.ContextFlags & portion & 0xFFFF) != 0;
}

//--------------------------------------------------------------------------
// (tid -> info)
struct threads_t: public std::map<DWORD, thread_info_t>
{
  thread_info_t *get(DWORD tid)
  {
    const iterator it = find(tid);
    if ( it == end() )
      return nullptr;
    return &it->second;
  }
};

//--------------------------------------------------------------------------
typedef qvector<thread_info_t> threadvec_t;

//--------------------------------------------------------------------------
// structure for the internal breakpoint information for threads
struct internal_bpt_info_t
{
  int count;            // number of times this breakpoint is 'set'
  uchar orig_bytes[BPT_CODE_SIZE]; // original byte values
};
typedef std::map<ea_t, internal_bpt_info_t> bpt_info_t;

//--------------------------------------------------------------------------
typedef int (*process_cb_t)(debmod_t *, PROCESSENTRY32 *pe32, void *ud);
typedef int (*module_cb_t)(debmod_t *, MODULEENTRY32 *me32, void *ud);

//----------------------------------------------------------------------------
// A live PDB session, that will be used remotely (typically by non-windows machines).
struct pdb_remote_session_t;
void close_pdb_remote_session(pdb_remote_session_t *);

// Wow64-specific events
#ifndef STATUS_WX86_BREAKPOINT
#  define STATUS_WX86_BREAKPOINT 0x4000001f
#endif
#ifndef STATUS_WX86_SINGLE_STEP
#  define STATUS_WX86_SINGLE_STEP 0x4000001e
#endif

//-------------------------------------------------------------------------
struct machine_thread_state_t;
struct machine_float_state_t;

//--------------------------------------------------------------------------
class win32_debmod_t : public winbase_debmod_t
{
  typedef winbase_debmod_t inherited;

  gdecode_t get_debug_event(debug_event_t *event, int timeout_ms);
  void check_thread(bool must_be_main_thread) const;
  void add_thread(const CREATE_THREAD_DEBUG_INFO &thr_info, thid_t tid);
  void install_callgate_workaround(thread_info_t *ti, const debug_event_t *event);
  int describe_stack_segment(
        thid_t tid,
        images_t &thr_ranges,
        images_t &cls_ranges,
        const _NT_TIB &tib,
        const char *pref);
  void update_thread_names(thread_name_vec_t *thr_names);

  bool get_pe_exports_from_path(
        const char *path,
        linput_t *li,
        ea_t imagebase,
        name_info_t &ni,
        const char *exported_name=nullptr) const;

public:
  // debugged process information
  qstring process_path;
  HANDLE thread_handle;
  HANDLE redirin_handle;
  HANDLE redirout_handle;
  attach_status_t attach_status;
  HANDLE attach_evid;
  int8 expecting_debug_break;
  bool stop_at_ntdll_bpts;

  images_t curproc; // image of the running process
  images_t dlls; // list of loaded DLLs
  images_t images; // list of detected PE images
  images_t thread_ranges; // list of ranges related to threads
  images_t class_ranges;  // list of ranges related to class names

  easet_t dlls_to_import; // list of dlls to import information from
  modinfo_t binary_to_import; // executable to import information from

  bpt_info_t thread_bpts;

  threads_t threads;

  // ID of a thread for which we must emulate a STEP event on XP (using a breakpoint)
  thid_t winxp_step_thread;

  CREATE_PROCESS_DEBUG_INFO cpdi;

  debug_event_t *in_event; // current debug event
  bool fake_suspend_event;
  bool exiting;
  bool pause_requested;
  procinfo_vec_t processes;

  // threads suspended by the fiber created for restoring broken connections
  threadvec_t _suspended_threads;
  // event to wait until the broken connection is completely restored
  HANDLE broken_event_handle;
  context_helper_t context_helper;

  // Module specific methods, to be implemented
  virtual void idaapi dbg_set_debugging(bool _debug_debugger) override;
  virtual drc_t idaapi dbg_init(uint32_t *flags2, qstring *errbuf) override;
  virtual void idaapi dbg_term(void) override;
  virtual drc_t idaapi dbg_detach_process(void) override;
  virtual drc_t idaapi dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf) override;
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms) override;
  virtual drc_t idaapi dbg_attach_process(
        pid_t process_id,
        int event_id,
        int flags,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_prepare_to_pause_process(qstring *errbuf) override;
  virtual drc_t idaapi dbg_exit_process(qstring *errbuf) override;
  virtual drc_t idaapi dbg_continue_after_event(const debug_event_t *event) override;
  virtual void idaapi dbg_stopped_at_debug_event(
        import_infos_t *infos,
        bool dlls_added,
        thread_name_vec_t *thr_names) override;
  virtual drc_t idaapi dbg_thread_suspend(thid_t thread_id) override;
  virtual drc_t idaapi dbg_thread_continue(thid_t thread_id) override;
  virtual drc_t idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod) override;
  virtual drc_t idaapi dbg_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t *values,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf) override;

  virtual drc_t idaapi dbg_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value, qstring *errbuf) override;
  virtual drc_t idaapi dbg_get_memory_info(meminfo_vec_t &ranges, qstring *errbuf) override;
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring *errbuf) override;
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring *errbuf) override;
  virtual int idaapi dbg_add_bpt(bytevec_t *orig_bytes, bpttype_t type, ea_t ea, int len) override;
  virtual int idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) override;
  virtual int idaapi handle_ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize) override;
  //
  win32_debmod_t();
  ~win32_debmod_t() { cleanup(); }

  virtual void init_reg_ctx(void) override;

  bool get_thread_state(
        context_holder_t *out_ctxh,
        machine_thread_state_t *out_regs,
        machine_float_state_t *out_floats,
        thid_t tid,
        int clsmask);
  bool set_thread_state(
        const machine_thread_state_t &regs,
        const machine_float_state_t &floats,
        const context_holder_t &ctxh,
        thid_t tid,
        int clsmask);

  void handle_pdb_thread_request(void *data);
  uint32 calc_imagesize(eanat_t base);
  bool get_filename_for(
        char *buf,
        size_t bufsize,
        eanat_t image_name_ea,
        bool use_unicode,
        eanat_t image_base);
  ea_t get_dll_export(
        const images_t &dlls,
        ea_t imagebase,
        const char *exported_name);

  bool create_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        bool is_gui,
        bool hide_window,
        PROCESS_INFORMATION *ProcessInformation);

  void show_debug_event(const DEBUG_EVENT &ev);

  ssize_t _read_memory(eanat_t ea, void *buffer, size_t size, bool suspend = false);
  ssize_t _write_memory(eanat_t ea, const void *buffer, size_t size, bool suspend = false);

  int rdmsr(int reg, uint64 *value);
  int wrmsr(int reg, uint64 value);
  int kldbgdrv_access_msr(struct SYSDBG_MSR *msr, bool write);

  // !! OVERWRITTEN METHODS !!
  bool refresh_hwbpts();

  // Utility methods
  gdecode_t handle_exception(debug_event_t *event,
    const EXCEPTION_RECORD &er,
    bool was_thread_bpt,
    bool firsttime);
  ssize_t access_memory(eanat_t ea, void *buffer, ssize_t size, bool write, bool suspend);
  inline void resume_all_threads(bool raw = false);
  inline void suspend_all_threads(bool raw = false);
  size_t add_dll(image_info_t &ii);
  bool module_present(const char *modname);
  HANDLE get_thread_handle(thid_t tid);
  static int get_dmi_cb(debmod_t *sess, MODULEENTRY32 *me32, void *ud);
  void get_debugged_module_info(modinfo_t *dmi);
  int for_each_module(DWORD pid, module_cb_t module_cb, void *ud);
  bool myCloseHandle(HANDLE &h);
  void cleanup(void);
  const char *get_range_name(const images_t &images, const range_t *range) const;
  void restore_original_bytes(ea_t ea, bool really_restore = true);
  int save_original_bytes(ea_t ea);
  bool set_thread_bpt(thread_info_t &ti, ea_t ea);
  bool del_thread_bpt(thread_info_t &ti, ea_t ea);
  bool del_thread_bpts(ea_t ea);
  bool has_bpt_at(ea_t ea);
  bool can_access(ea_t addr);
  ea_t get_kernel_bpt_ea(ea_t ea, thid_t tid);
  void create_attach_event(debug_event_t *event, bool attached);
  void create_start_event(debug_event_t *event);
  bool check_for_hwbpt(debug_event_t *event, bool is_stepping=false);
  ea_t get_region_info(ea_t ea, memory_info_t *info);
  bool get_dll_exports(
        const images_t &dlls,
        ea_t imagebase,
        name_info_t &ni,
        const char *exported_name = nullptr);
  bool get_filename_from_process(
        eanat_t name_ea,
        bool is_unicode,
        char *buf,
        size_t bufsize);
  bool get_debug_string(const DEBUG_EVENT &ev, char *buf, size_t bufsize);
  int add_thread_ranges(
        thid_t tid,
        images_t &thread_ranges,
        images_t &class_ranges);
  ea_t get_pe_header(eanat_t imagebase, peheader_t *nh);
  bool get_pe_export_name_from_process(
        eanat_t imagebase,
        char *name,
        size_t namesize);

  void show_exception_record(const EXCEPTION_RECORD &er, int level=0);

  eanat_t pstos0(eanat_t ea);
  eanat_t s0tops(eanat_t ea);

  bool prepare_to_stop_process(debug_event_t *, const threads_t &);
  bool disable_hwbpts();
  bool enable_hwbpts();
  bool may_write(ea_t ea);
  LPVOID correct_exe_image_base(LPVOID base);
  bool clear_tbit(thread_info_t &th);
  void enqueue_event(const debug_event_t &ev, queue_pos_t pos);

  void suspend_running_threads(threadvec_t &suspended);
  void resume_suspended_threads(threadvec_t suspended) const;
  bool reopen_threads(void);

  virtual bool idaapi write_registers(
        thid_t thread_id,
        int start,
        int count,
        const regval_t *values) override;

  virtual bool idaapi dbg_prepare_broken_connection(void) override;
  virtual bool idaapi dbg_continue_broken_connection(pid_t pid) override;

  qvector<pdb_remote_session_t*> pdb_remote_sessions;
  pdb_remote_session_t *get_pdb_session(int id);
  void delete_pdb_session(int id);

  ea_t ptr_to_ea(const void *ptr) { return trunc_uval(EA_T(ptr)); }

protected:
  virtual int dbg_freeze_threads_except(thid_t tid) override;
  virtual int dbg_thaw_threads_except(thid_t tid) override;
};

ea_t s0tops(ea_t ea);

#endif

