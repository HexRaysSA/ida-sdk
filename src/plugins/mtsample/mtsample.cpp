/*
 *  This is a sample multi-threaded plugin module
 *
 *  It creates 3 new threads. Each threads sleeps and prints a message in a loop
 *
 */

#ifdef __NT__
#include <windows.h>
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#ifdef __NT__
#include <windows.h>
#endif


//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  qthread_t children[10] = { nullptr };
  int nchilds = 0;

  ~plugin_ctx_t() { term(); }
  void term()
  {
    if ( nchilds > 0 )
    {
      msg("Killing all threads\n");
      for ( int i=0; i < nchilds; i++ )
      {
        qthread_kill(children[i]);
        qthread_join(children[i]);
        // cancel all pending requests from the killed thread
        cancel_thread_exec_requests(children[i]);
        qthread_free(children[i]);
      }
      msg("Killed all threads\n");
      nchilds = 0;
    }
  }
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
static void say_hello(size_t id, qthread_t tid, int cnt)
{
  struct ida_local hello_t : public exec_request_t
  {
    uint64 nsecs;
    size_t id;
    qthread_t tid;
    int cnt;
    ssize_t idaapi execute(void) override
    {
      uint64 now = get_nsec_stamp();
      int64 delay = now - nsecs;
      msg("Hello %d from thread %" FMT_Z ". tid=%p. current tid=%p (delay=%" FMT_64 "d)\n",
          cnt, id, tid, qthread_self(), delay);
      return 0;
    }
    hello_t(size_t _id, qthread_t _tid, int _cnt) : id(_id), tid(_tid), cnt(_cnt)
    {
      nsecs = get_nsec_stamp();
    }
  };
  hello_t hi(id, tid, cnt);

  int mff;
  switch ( id % 3 )
  {
    case 0: mff = MFF_FAST;  break;
    case 1: mff = MFF_READ;  break;
    default:
    case 2: mff = MFF_WRITE; break;
  }
  execute_sync(hi, mff);
}

//--------------------------------------------------------------------------
static int idaapi thread_func(void *ud)
{
  size_t id = (size_t)ud;
  qthread_t tid = qthread_self();
  int cnt = 0;
  srand(id ^ (size_t)tid);
  while ( true )
  {
    say_hello(id, tid, cnt++);
    int r = rand() % 1000;
    qsleep(r);
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  if ( nchilds == 0 )
  {
    children[nchilds] = qthread_create(thread_func, (void *)(ssize_t)nchilds); nchilds++;
    children[nchilds] = qthread_create(thread_func, (void *)(ssize_t)nchilds); nchilds++;
    children[nchilds] = qthread_create(thread_func, (void *)(ssize_t)nchilds); nchilds++;
    msg("Three new threads have been created. Main thread id %p\n", qthread_self());
    for ( int i=0; i < 5; i++ )
      say_hello(-1, 0, 0);
  }
  else
  {
    term();
  }
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Multi-threaded sample", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
