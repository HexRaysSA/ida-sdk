#ifndef __TILFUNCS__
#define __TILFUNCS__

#include "../../plugins/pdb/pdb.hpp"
#include "../../plugins/pdb/msdia.hpp"

#define SEM_NO_WAIT     0

//----------------------------------------------------------------------------
enum fetch_type_t
{
  FT_NONE,
  FT_OPEN,
  FT_SYMBOL,
  FT_CHILDREN,
  FT_LINES_BY_VA,
  FT_LINES_BY_COORDS,
  FT_SYMBOLS_AT_VA,
  FT_FILE_COMPILANDS,
  FT_FILE_PATH,
  FT_SYMBOL_FILES,
  FT_FIND_FILES,
};

struct pdb_remote_session_t;
//----------------------------------------------------------------------------
// We have to interact with DIA from a single thread.
// We cannot do it from the main thread because the very first request to
// open a pdb file may take very long time. Therefore we handle everything
// from a dedicated thread.
struct pdb_thread_t
{
  pdb_thread_t();
  ~pdb_thread_t();

  qsemaphore_t accepting_request;
  qsemaphore_t request_available;
  pdb_remote_session_t *pdb_rsess;

  // qsemaphore_t req_ready; // main thread has a request for pdb thread
  // qsemaphore_t resp_ready; // pdb thread done with the request
  bool is_running() const;
  void stop();
  void kill(); // Kill thread, if running. Should be avoided.

  void start_if_needed();

private:
  qthread_t thread_handle;
  qmutex_t opener_mutex;
};
extern pdb_thread_t pdb_thread;

//----------------------------------------------------------------------------
enum pdb_rr_kind_t
{
  NONE,
  READ_INPUT_FILE,
  READ_MEMORY
};

//----------------------------------------------------------------------------
// The 'pdb_remote_session_t' acts as a holder of the actual DIA session,
// and forwards all requests for PDB information to the PDB thread.
struct pdb_remote_session_t
{
  pdb_remote_session_t();
  ~pdb_remote_session_t();

  // request from pdb_thread to the main thread to read memory or file
  struct client_read_request_t
  {
    client_read_request_t();
    ~client_read_request_t();

    pdb_rr_kind_t kind;
    uint64 off_ea;    // offset or address to read
    void *buffer;     // buffer to read into
    uint32 size;      // number of bytes to read / read
    bool result;
    qsemaphore_t read_req;
    qsemaphore_t read_resp;

    bool pending() const { return qsem_wait(read_req, SEM_NO_WAIT); }
    void read_complete()  const { qsem_post(read_resp); }
    bool request_read(pdb_rr_kind_t kind, uint64 off_ea, uint32 count, void *buffer, uint32 *read);
  };
  client_read_request_t client_read_request;

  bool open(const compiler_info_t &_cc, const pdbargs_t &args);
  bool fetch_symbol(uint32 id);
  bool fetch_children(uint32 id, enum SymTagEnum children_type);
  bool fetch_lines_by_va(ea_t va, uint64 length);
  bool fetch_lines_by_coords(uint32 file_id, uint32 lnnum, uint32 colnum);
  bool fetch_symbols_at_va(ea_t va, uint64 length, enum SymTagEnum type);
  bool fetch_file_compilands(uint32 file_id);
  bool fetch_file_path(uint32 file_id);
  bool fetch_symbol_files(uint32 id);
  bool fetch_files(const char *fname);

  void stop();        // finish open file request as soon as possible
  bool perform(void); // in PDB thread!
  bool is_done() const { return qsem_wait(fetch_complete, SEM_NO_WAIT); }

  // values requested to fetch by the main thread for the pdb thread
  fetch_type_t fetch_type;
  uint32 fetch_id;
  ea_t fetch_va;
  uint64 fetch_length;
  uint32 fetch_file_id;
  uint32 fetch_lnnum;
  uint32 fetch_colnum;
  enum SymTagEnum fetch_symbol_type;
  qstring fetch_str;
  bool fetch_ok;        // return value
  bool is_opening;

  pdb_session_ref_t session_ref;    // The underlying PDB session
  compiler_info_t compiler_info;
  pdbargs_t args;

  bytevec_t storage;     // Storage area where the results produced by fetch_*()
                         // will be stored.

  int pack_symbol(IDiaSymbol *sym);
  qsemaphore_t fetch_complete; // pdb thread has finished call to perform()

  int get_id() const { return session_id; }

private:
  bytevec_t sym_storage; // A smaller storage, meant to hold a single packed symbol.
                         // Just there to avoid many malloc()s.
  bool request_pdb_thread(bool wait_for_completion = true);
  int session_id;
  static int last_id;
};

#endif // __TILFUNCS__
