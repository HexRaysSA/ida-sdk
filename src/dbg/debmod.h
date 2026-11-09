#ifndef __DEBUGGER_MODULE__
#define __DEBUGGER_MODULE__

//
//
//      This is the base debmod_t class definition
//      From this class all debugger code must inherite and specialize
//
//      Some OS specific functions must be implemented:
//        bool init_subsystem();
//        bool term_subsystem();
//        debmod_t *create_debug_session(void *);
//        int create_thread(thread_cb_t thread_cb, void *context);
//

#include <deque>

#include <pro.h>
#include <err.h>
#include <idd.hpp>
#include <network.hpp>

//--------------------------------------------------------------------------
struct regctx_t;
extern debugger_t debugger;

//--------------------------------------------------------------------------
struct name_info_t
{
  eavec_t addrs;
  qvector<char *> names;
  void clear(void)
  {
    addrs.clear();
    names.clear();
  }
};

//--------------------------------------------------------------------------
// Extended process info
struct ext_process_info_t : public process_info_t
{
  int addrsize;     // process bitness 32bit - 4, 64bit - 8, 0 - unknown
  qstring ext_name; // human-readable name (e.g. with command line agrs)
  void copy_to(process_info_t *dst)
  {
    dst->pid = pid;
    dst->name = ext_name.empty() ? name : ext_name;
  }
};
typedef qvector<ext_process_info_t> procvec_t;

//--------------------------------------------------------------------------
// Very simple class to store pending events
enum queue_pos_t
{
  IN_FRONT,
  IN_BACK
};

//--------------------------------------------------------------------------
struct pagebpt_data_t
{
  ea_t ea;              // address of the bpt as specified by the user
  ea_t page_ea;         // real address of the bpt as written to the process
  int user_len;         // breakpoint length as specified by the user
  int aligned_len;      // breakpoint length aligned to the page size
  int real_len;         // real length of the breakpoint as written to the process
  uint32 old_prot;      // old page protections (before writing the bpt to the process)
                        // if 0, the bpt has not been written to the process yet.
  uint32 new_prot;      // new page protections (when the bpt is active)
  bpttype_t type;       // breakpoint type
};

// Information about page breakpoints is stored in this data structure.
// The map is indexed by the page start address (not the address specified
// by the user!)
typedef std::map<ea_t, pagebpt_data_t> page_bpts_t; // page_ea -> bpt info
typedef qvector<page_bpts_t::iterator> pbpt_iterators_t; // list of iterators into page_bpts_t

//--------------------------------------------------------------------------
// set of addresses
typedef std::set<ea_t> easet_t;

//-------------------------------------------------------------------------
class idc_value_t;
class rpc_engine_t;
error_t idaapi idc_get_reg_value(idc_value_t *argv, idc_value_t *r);
error_t idaapi idc_set_reg_value(idc_value_t *argv, idc_value_t *r);
void report_idc_error(rpc_engine_t *rpc, ea_t ea, error_t code, ssize_t errval, const char *errprm);

// IDC function name that is exported by a debugger module
// to allow scripts to send debugger commands
#define IDC_SENDDBG_CMD "send_dbg_command"
#define IDC_READ_MSR    "read_msr"
#define IDC_WRITE_MSR   "write_msr"
#define IDC_STEP_BACK   "step_back"
#define IDC_SET_TEV     "set_current_tev"
#define IDC_GET_TEV     "get_current_tev"

// A macro to convert a pointer to ea_t without sign extension.
#define EA_T(ptr) (ea_t)(size_t)(ptr)

//--------------------------------------------------------------------------
//-V:debmod_bpt_t:730 not all members of a class are initialized inside the constructor: saved
struct debmod_bpt_t
{
  ea_t ea;
  uchar saved[8]; // size of the biggest supported bpt size (PPC64)
  uchar nsaved;
  int bid;        // (epoc) breakpoint id (from TRK)
  debmod_bpt_t() : ea(BADADDR), nsaved(0), bid(0) {}
  debmod_bpt_t(ea_t _ea, uchar _nsaved) : ea(_ea), nsaved(_nsaved), bid(0) { QASSERT(1796, nsaved < sizeof(saved)); }
};
typedef std::map<ea_t, debmod_bpt_t> debmodbpt_map_t;

//--------------------------------------------------------------------------
struct eventlist_t : public std::deque<debug_event_t>
{
public:
  // save a pending event
  void enqueue(const debug_event_t &ev, queue_pos_t pos)
  {
    if ( pos != IN_BACK )
      push_front(ev);
    else
      push_back(ev);
  }

  // retrieve a pending event
  bool retrieve(debug_event_t *event)
  {
    if ( empty() )
      return false;
    // get the first event and return it
    *event = front();
    pop_front();
    return true;
  }
};

//--------------------------------------------------------------------------
int send_ioctl(rpc_engine_t *rpc, int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
int send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty);
int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
void set_arm_thumb_modes(ea_t *addrs, int qty);
char *debug_event_str(const debug_event_t *ev, char *buf, size_t bufsize);
char *debug_event_str(const debug_event_t *ev); // returns static buf
int get_default_app_addrsize();
void update_idd_registers();

//--------------------------------------------------------------------------
// describes a dll to be imported
struct import_request_t
{
  ea_t base;
  qstring path;
  bytevec_t uuid;
  import_request_t(ea_t _base, const qstring &_path, const bytevec_t &_uuid)
    : base(_base), path(_path), uuid(_uuid) {}
};
DECLARE_TYPE_AS_MOVABLE(import_request_t);
typedef qvector<import_request_t> import_infos_t;
int import_dll(const import_request_t &req);

//--------------------------------------------------------------------------
struct regctx_entry_t
{
  enum type_t
  {
    IVAL = 0,
    FVAL = 1,
    DATA = 2,
    FUNC = 3,
  } type;
  int reg_class;
  int reg_idx;
  union
  {
    struct
    {
      size_t offset_in_ctx;
      size_t size_in_ctx;
      size_t reg_size;
    };
    struct
    {
      void (*read_func)(const regctx_t *, regval_t *, void *);
      void (*write_func)(regctx_t *, const regval_t *, void *);
      void *user_data;
    };
  };

  uint64_t truncate_ival(uint64_t ival) const
  {
    switch ( reg_size )
    {
      case 1: ival = uint8_t(ival); break;
      case 2: ival = uint16_t(ival); break;
      case 4: ival = uint32_t(ival); break;
    }
    return ival;
  }

  void read(regval_t *value, const uint8_t *ptr) const
  {
    if ( type == regctx_entry_t::FUNC )
    {
      read_func((regctx_t *) ptr, value, user_data);
    }
    else
    {
      const uint8_t *p = ptr + offset_in_ctx;
      switch ( type )
      {
        case regctx_entry_t::IVAL:
          {
            uint64_t ival = 0;
            switch ( size_in_ctx )
            {
              case 1: ival = *(uint8_t *)p; break;
              case 2: ival = *(uint16_t *)p; break;
              case 4: ival = *(uint32_t *)p; break;
              case 8: ival = *(uint64_t *)p; break;
            }
            ival = truncate_ival(ival);
            value->ival = ival;
          }
          break;
        case regctx_entry_t::FVAL:
          value->set_bytes(p, size_in_ctx, RVT_FLOAT);
          break;
        case regctx_entry_t::DATA:
          value->set_bytes(p, size_in_ctx);
          break;
        case regctx_entry_t::FUNC:
          // never happens; makes compiler happy.
          break;
      }
    }
  }

  bool patch(uint8_t *ptr, const regval_t *value) const
  {
    if ( type == regctx_entry_t::FUNC )
    {
      write_func((regctx_t *) ptr, value, user_data);
    }
    else
    {
      int dsize;
      uint8_t *p = ptr + offset_in_ctx;
      switch ( type )
      {
        case regctx_entry_t::IVAL:
          {
            uint64_t ival = value->ival;
            ival = truncate_ival(ival);
            switch ( size_in_ctx )
            {
              case 1: *(uint8_t *)p = ival; break;
              case 2: *(uint16_t *)p = ival; break;
              case 4: *(uint32_t *)p = ival; break;
              case 8: *(uint64_t *)p = ival; break;
            }
          }
          break;
        case regctx_entry_t::FVAL:
        case regctx_entry_t::DATA:
          dsize = value->get_data_size();
          if ( dsize != size_in_ctx )
            return false;
          memcpy(p, value->get_data(), dsize);
          break;
        case regctx_entry_t::FUNC:
          // never happens; makes compiler happy.
          INTERR(3257);
      }
    }
    return true;
  }
};
DECLARE_TYPE_AS_MOVABLE(regctx_entry_t);
typedef qvector<regctx_entry_t> reg_ctx_entries_t;

//--------------------------------------------------------------------------
struct regctx_base_t
{
  dynamic_register_set_t &idaregs; // linked to debmod_t's variable of the same name
  reg_ctx_entries_t entries;
  int clsmask = 0;
  thid_t tid = 0;

  regctx_base_t(dynamic_register_set_t &_idaregs) : idaregs(_idaregs) {}
  virtual ~regctx_base_t() {}

  void setup(thid_t _tid, int _clsmask=0)
  {
    tid = _tid;
    clsmask = _clsmask;
  }

  void setup_reg(int dyn_reg_idx)
  {
    clsmask |= entries[dyn_reg_idx].reg_class;
  }

  void add_idareg(const register_info_t &ri)
  {
    idaregs.add_register(ri.name,
                         ri.flags,
                         ri.dtype,
                         ri.register_class,
                         ri.bit_strings,
                         ri.default_bit_strings_mask);
  }

  size_t add_entry(
        regctx_entry_t::type_t type,
        const register_info_t &ri,
        size_t offset_in_ctx,
        size_t size_in_ctx,
        size_t reg_size)
  {
    size_t dyn_reg_idx = entries.size();
    regctx_entry_t &entry = entries.push_back();
    entry.type = type;
    entry.reg_class = ri.register_class;
    entry.reg_idx = dyn_reg_idx;
    entry.offset_in_ctx = offset_in_ctx;
    entry.size_in_ctx = size_in_ctx;
    entry.reg_size = reg_size;
    add_idareg(ri);
    return dyn_reg_idx;
  }

  size_t add_ival(const register_info_t &ri, size_t offset_in_ctx, size_t size_in_ctx)
  {
    QASSERT(1797, size_in_ctx <= sizeof(regval_t::ival));
    size_t reg_size = ri.dtype == dt_word  ? 2
                    : ri.dtype == dt_dword ? 4
                    : ri.dtype == dt_qword ? 8
                    :                        0;
    QASSERT(1798, reg_size != 0);
    return add_entry(regctx_entry_t::IVAL, ri, offset_in_ctx, size_in_ctx, reg_size);
  }

  size_t add_fval(const register_info_t &ri, size_t offset_in_ctx, size_t size_in_ctx)
  {
    return add_entry(regctx_entry_t::FVAL, ri, offset_in_ctx, size_in_ctx, size_in_ctx);
  }

  size_t add_data(const register_info_t &ri, size_t offset_in_ctx, size_t size_in_ctx)
  {
    return add_entry(regctx_entry_t::DATA, ri, offset_in_ctx, size_in_ctx, size_in_ctx);
  }

  size_t add_func(
        register_info_t &ri,
        void (*read_func)(const regctx_t *, regval_t *, void *),
        void (*write_func)(regctx_t *, const regval_t *, void *),
        void *user_data=nullptr)
  {
    size_t dyn_reg_idx = entries.size();
    regctx_entry_t &entry = entries.push_back();
    entry.type = regctx_entry_t::FUNC;
    entry.reg_class = ri.register_class;
    entry.reg_idx = dyn_reg_idx;
    entry.read_func = read_func;
    entry.write_func = write_func;
    entry.user_data = user_data;
    add_idareg(ri);
    return dyn_reg_idx;
  }

  void read_all(regval_t *values)
  {
    for ( const regctx_entry_t &entry: entries )
      if ( (clsmask & entry.reg_class) != 0 )
        entry.read(&values[entry.reg_idx], (const uint8_t *) this);
  }

  bool patch(int dyn_reg_idx, const regval_t *value)
  {
    QASSERT(3258, dyn_reg_idx < entries.size());
    return entries[dyn_reg_idx].patch((uint8_t *) this, value);
  }
  virtual bool init() = 0;
  virtual bool load() = 0;
  virtual bool store() = 0;
};

//--------------------------------------------------------------------------
// Main class to represent a debugger module
class debmod_t
{
  ea_helper_t _eah;

protected:
//  processor_t &ph;
  typedef std::map<int, regval_t> regval_map_t;
  qvector<exception_info_t> exceptions;
  name_info_t dn_names;
  // Pending events. currently used only to store
  // exceptions that happen while attaching
  eventlist_t events;
  // The last event received via a successful get_debug_event()
  debug_event_t last_event;

  // debugged process attributes (may be changed after process start/attach)
  debapp_attrs_t debapp_attrs;

  procvec_t proclist;

  // appcall contexts
  struct call_context_t
  {
    regvals_t saved_regs;
    ea_t sp = BADADDR;
    ea_t ctrl_ea = BADADDR;
    bool regs_spoiled = false;
  };
  typedef qstack<call_context_t> call_contexts_t;
  typedef std::map<thid_t, call_contexts_t> appcalls_t;
  appcalls_t appcalls;

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
  {
    return ::send_ioctl(rpc, fn, buf, size, poutbuf, poutsize);
  }
  // If an IDC error occurs: we cannot prepare an error message on the server
  // side because we do not have access to error strings (they are in ida.hlp).
  // We pass the error code to IDA (with eventual arguments) so it can prepare
  // a nice error message for the user
  void report_idc_error(ea_t ea, error_t code, ssize_t errval, const char *errprm)
  {
    return ::report_idc_error(rpc, ea, code, errval, errprm);
  }

  typedef std::map<ea_t, lowcnd_t> lowcnds_t;
  lowcnds_t cndmap;
  eavec_t handling_lowcnds;
  bool evaluate_and_handle_lowcnd(debug_event_t *event, int elc_flags=0);
  bool handle_lowcnd(lowcnd_t *lc, debug_event_t *event, int elc_flags);
#define ELC_KEEP_EIP  0x0001 // do not reset eip before stepping
#define ELC_KEEP_SUSP 0x0002 // keep suspended state, do not resume after stepping

  // helper functions for programmatical single stepping
  virtual drc_t dbg_perform_single_step(debug_event_t *event, const insn_t &ins);
  virtual int dbg_freeze_threads_except(thid_t) { return 0; }
  virtual int dbg_thaw_threads_except(thid_t) { return 0; }
  drc_t resume_app_and_get_event(debug_event_t *dev);
  void set_platform(const char *platform_name);

  // return number of processes, -1 - not implemented
  virtual int idaapi get_process_list(procvec_t *proclist, qstring *errbuf);

public:
  meminfo_vec_t old_ranges;
  rpc_engine_t *rpc = nullptr;
  bytevec_t bpt_code; // Must be initialized by derived classes.
  debmodbpt_map_t bpts;
  update_bpt_vec_t deleted_bpts; // deleted bpts in the last update_bpts() call
  qstring input_file_path;
  page_bpts_t page_bpts;
  pid_t pid = -1;

  //------------------------------------
  // Dynamic register set for debugger_t
  //------------------------------------
  regctx_base_t *reg_ctx = nullptr;
  dynamic_register_set_t idaregs;
  int static_nregs = 0; // if dynamic registers are not used, number of static registers

  // indexes of sp and program counter registers.
  // Must be initialized by derived classes.
  int sp_idx = -1;
  int pc_idx = -1;
  int fp_idx = -1; // index of frame pointer register

  // Breakpoint code.
  int debugger_flags = 0;
  bool broken_connection = false;
  bool debug_debugger = false;
  bool is_dll = false; // Is dynamic library?

  static bool reuse_broken_connections;

  // will either send as msg/warning/error through callui,
  // or through 'rpc' if it is present.
  DEFINE_ALL_NOTIFICATION_FUNCTIONS(rpc);
  AS_PRINTF(3,0) static ssize_t dvnotif(int code, rpc_engine_t *rpc, const char *format, va_list va);

  // if bpt EA was deleted then bpt raised in the same place for the
  // same thread does not belong to IDA
  bool is_ida_bpt(ea_t ea, thid_t tid)
  {
    if ( bpts.find(ea) != bpts.end() )
      return true;
    update_bpt_info_t b;
    b.ea = ea;
    return deleted_bpts.find(b) != deleted_bpts.end()
        && (last_event.eid() != BREAKPOINT
         || last_event.ea != ea
         || last_event.tid != tid);
  }

  int nregs() const { return idaregs.empty() ? static_nregs : idaregs.nregs(); }

  //------------------------------------
  // Constructors and destructors
  //------------------------------------
  debmod_t();
  virtual ~debmod_t() { cleanup(); }

  //------------------------------------
  // Debug names methods
  //------------------------------------
  void clear_debug_names();
  name_info_t *get_debug_names();
  void save_debug_name(ea_t ea, const char *name);
  int set_debug_names();
  int send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty);
  int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
  ea_t find_debug_name(const char *name) const;
  //------------------------------------
  // Utility methods
  //------------------------------------
  void cleanup(void);
  AS_PRINTF(2, 3) void debdeb(const char *format, ...);
  AS_PRINTF(2, 3) bool deberr(const char *format, ...);
  bool same_as_oldmemcfg(const meminfo_vec_t &ranges) const;
  void save_oldmemcfg(const meminfo_vec_t &ranges);
  bool continue_after_last_event(bool handled = true);
  lowcnd_t *get_failed_lowcnd(thid_t tid, ea_t ea);
  page_bpts_t::iterator find_page_bpt(ea_t ea, int size=1);
  bool del_page_bpt(ea_t ea, bpttype_t type);
  void enable_page_bpts(bool enable);
  ea_t calc_page_base(ea_t ea) { return align_down(ea, dbg_memory_page_size()); }
  void log_exception(const debug_event_t *ev, const exception_info_t *ei);
  uint64 probe_file_size(int fn, uint64 step);
  void set_input_path(const char *input_path);
  int read_bpt_orgbytes(bytevec_t *buf, ea_t ea, int len);

  //------------------------------------
  // Shared methods
  //------------------------------------
  virtual bool check_input_file_crc32(uint32 orig_crc);
  virtual const exception_info_t *find_exception(int code);
  virtual bool get_exception_name(int code, char *buf, size_t bufsize);
  virtual drc_t idaapi dbg_get_processes(procinfo_vec_t *info, qstring *errbuf);

  //------------------------------------
  // Methods to be implemented
  //------------------------------------
  virtual void idaapi dbg_set_debugging(bool _debug_debugger) = 0;
  virtual drc_t idaapi dbg_init(uint32_t *flags2, qstring *errbuf) = 0;
  virtual void idaapi dbg_term(void) = 0;
  virtual drc_t idaapi dbg_detach_process(void) = 0;
  virtual drc_t idaapi dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf) = 0;
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_msecs) = 0;
  virtual drc_t idaapi dbg_attach_process(pid_t process_id, int event_id, int flags, qstring *errbuf) = 0;
  virtual drc_t idaapi dbg_prepare_to_pause_process(qstring *errbuf) = 0;
  virtual drc_t idaapi dbg_exit_process(qstring *errbuf) = 0;
  virtual drc_t idaapi dbg_continue_after_event(const debug_event_t *event) = 0;
  virtual void idaapi dbg_set_exception_info(const exception_info_t *info, int qty);
  virtual void idaapi dbg_stopped_at_debug_event(import_infos_t *infos, bool dlls_added, thread_name_vec_t *thr_names) = 0;
  virtual drc_t idaapi dbg_thread_suspend(thid_t thread_id) = 0;
  virtual drc_t idaapi dbg_thread_continue(thid_t thread_id) = 0;
  virtual drc_t idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod) = 0;
  virtual drc_t idaapi dbg_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t *values,
        qstring *errbuf) = 0;
  virtual drc_t idaapi dbg_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf) = 0;
  virtual drc_t idaapi dbg_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value, qstring *errbuf) = 0;
  virtual ea_t idaapi map_address(ea_t ea, const regval_t *, int /* regnum */) { return ea; }
  virtual drc_t idaapi dbg_get_memory_info(meminfo_vec_t &ranges, qstring *errbuf) = 0;
  virtual int idaapi dbg_get_scattered_image(scattered_image_t & /*si*/, ea_t /*base*/) { return -1; }
  virtual bool idaapi dbg_get_image_uuid(bytevec_t * /*uuid*/, ea_t /*base*/) { return false; }
  virtual ea_t idaapi dbg_get_segm_start(ea_t /*base*/, const qstring & /*segname*/) { return BADADDR; }
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring *errbuf) = 0;
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring *errbuf) = 0;
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) = 0;
  // for swbpts, len may be -1 (unknown size, for example arm/thumb mode) or bpt opcode length
  // dbg_add_bpt returns 2 if it adds a page bpt
  virtual int idaapi dbg_add_bpt(bytevec_t *orig_bytes, bpttype_t type, ea_t ea, int len) = 0;
  virtual int idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) = 0;
  virtual drc_t idaapi dbg_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel, qstring *errbuf);
  virtual int idaapi dbg_add_page_bpt(bpttype_t /*type*/, ea_t /*ea*/, int /*size*/) { return 0; }
  virtual bool idaapi dbg_enable_page_bpt(page_bpts_t::iterator /*p*/, bool /*enable*/) { return false; }
  virtual drc_t idaapi dbg_update_lowcnds(int *nupdated, const lowcnd_t *lowcnds, int nlowcnds, qstring *errbuf);
  virtual drc_t idaapi dbg_eval_lowcnd(thid_t tid, ea_t ea, qstring *errbuf);
  virtual int idaapi dbg_open_file(const char * /*file*/, uint64 * /*fsize*/, bool /*readonly*/) { return -1; }
  virtual void idaapi dbg_close_file(int /*fn*/) {}
  virtual ssize_t idaapi dbg_read_file(int /*fn*/, qoff64_t /*off*/, void * /*buf*/, size_t /*size*/) { return 0; }
  virtual ssize_t idaapi dbg_write_file(int /*fn*/, qoff64_t /*off*/, const void * /*buf*/, size_t /*size*/) { return 0; }
  virtual int idaapi handle_ioctl(
        int /*fn*/,
        const void * /*buf*/,
        size_t /*size*/,
        void ** /*outbuf*/,
        ssize_t * /*outsize*/)
  {
    return 0;
  }
  virtual int idaapi get_system_specific_errno() const; // this code must be acceptable by winerr()
  const char *winerr() const { return ::winerr(get_system_specific_errno()); }
  const char *winerr(int code) const { return ::winerr(code); }
  // dbg_update_call_stack can return
  //  - DRC_NONE, DRC_OK : see ev_update_call_stack event
  //  - DRC_FAILED : some permanent issue prevents the debugger to provide call staks
  //                 the flag DBG_HAS_UPDATE_CALL_STACK will be cleaned for the session
  //                 the return will be set to DRC_NONE to check the other options
  //                 the event will not be checked anymore for this debugging session
  virtual drc_t idaapi dbg_update_call_stack(thid_t, call_stack_t *) { return DRC_NONE; }
  virtual ea_t idaapi dbg_appcall(
        ea_t /*func_ea*/,
        thid_t /*tid*/,
        int /*stkarg_nbytes*/,
        const struct regobjs_t * /*regargs*/,
        struct relobj_t * /*stkargs*/,
        struct regobjs_t * /*retregs*/,
        qstring *errbuf,
        debug_event_t * /*event*/,
        int /*flags*/);
  virtual drc_t idaapi dbg_cleanup_appcall(thid_t /*tid*/);
  virtual bool idaapi write_registers(
        thid_t /*tid*/,
        int /*start*/,
        int /*count*/,
        const regval_t * /*values*/)
  {
    return false;
  }
  // finalize appcall stack image
  // input: stack image contains the return address at the beginning
  virtual int finalize_appcall_stack(call_context_t &, regval_map_t &, bytevec_t &) { return 0; }
  virtual ea_t calc_appcall_stack(const regvals_t &regvals);
  virtual bool should_stop_appcall(thid_t tid, const debug_event_t *event, ea_t ea);
  virtual bool should_suspend_at_exception(const debug_event_t *event, const exception_info_t *ei);
  virtual bool preprocess_appcall_cleanup(thid_t, call_context_t &) { return true; }
  virtual int get_regidx(const char *regname, int *clsmask) = 0;
  virtual uint32 dbg_memory_page_size(void) { return 0x1000; }
  virtual bool idaapi dbg_prepare_broken_connection(void) { return false; }
  virtual bool idaapi dbg_continue_broken_connection(pid_t) { old_ranges.clear(); return true; }
  virtual bool idaapi dbg_enable_trace(thid_t, bool, int) { return false; }
  virtual bool idaapi dbg_is_tracing_enabled(thid_t, int) { return false; }
  virtual int idaapi dbg_rexec(const char *cmdline);
  virtual void adjust_swbpt(ea_t *, int *) {}
  virtual void dbg_get_debapp_attrs(debapp_attrs_t *out_pattrs) const;
  virtual bool idaapi dbg_get_srcinfo_path(qstring * /*path*/, ea_t /*base*/) const { return false; }
  virtual bool import_dll(const import_request_t & /*req*/) { return false; }
  virtual drc_t idaapi dbg_bin_search(
        ea_t *ea,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &ptns,
        int srch_flags,
        qstring *errbuf);
  virtual void init_reg_ctx() {}
  virtual void term_reg_ctx()
  {
    if ( reg_ctx != nullptr )
    {
      delete reg_ctx;
      idaregs.clear();
    }
    reg_ctx = nullptr;
    update_idd_registers();
  }
  void init_dynamic_regs()
  {
    term_reg_ctx();
    init_reg_ctx();
    // take this opportunity to check that the derived class initialized
    // register related fields correctly
    QASSERT(30016, sp_idx != -1 && pc_idx != -1 && nregs() > 0);
    update_idd_registers();
  }
  virtual const register_info_t &get_reginfo(int regidx);


  bool restore_broken_breakpoints(void);
  void set_addr_size(int size)
  {
#ifdef __EA64__
    _eah.setup(size == 8);
#else
    QASSERT(2777, size < 8);
#endif
    debapp_attrs.addrsize = size;
  }
  void set_endianness(bool is_be) { debapp_attrs.is_be = is_be; }
  int get_addr_size() const { return debapp_attrs.addrsize; }
  bool is_64bit_app() const { return get_addr_size() == 8; }

  DEFINE_EA_HELPER_FUNCS(_eah)
};

//---------------------------------------------------------------------------

//
// Some functions, per OS implemented
//
bool init_subsystem();
bool term_subsystem();
debmod_t *create_debug_session(void *params);

//
// Processor specific init/term
//
void processor_specific_init(void);
void processor_specific_term(void);

// Perform an action on all existing debugger modules
struct debmod_visitor_t
{
  virtual int visit(debmod_t *debmod) = 0;
};
int for_all_debuggers(debmod_visitor_t &v);


//
// Utility functions
//

// Common method between MacOS and Linux to launch a process
drc_t idaapi maclnx_launch_process(
        debmod_t *debmod,
        const char *path,
        const char *args,
        const launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        void **child_pid,
        qstring *errbuf);

bool add_idc_funcs(const struct ext_idcfunc_t funcs[], size_t nfuncs, bool reg);

inline void form_envs(qstring *out, const launch_env_t *envs)
{
  for ( auto &env : *envs )
  {
    const char *p = strchr(env.begin(), '=');
    if ( p != nullptr )
    {
      out->append(env);
      out->append('\0');
    }
  }
  if ( !out->empty() )
    out->append('\0');
}

//
// Externs
//
extern debmod_t *idc_debmod;
extern thid_t idc_thread;

//---------------------------------------------------------------------------
// server.cpp
bool lock_begin();
bool lock_end();

// bool srv_lock_begin(void);
// bool srv_lock_end(void);

#endif
