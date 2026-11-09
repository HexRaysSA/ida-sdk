/*
* This is a sample plugin to demonstrate the UI requests and the process_ui_action()
* One process_ui_action() can be processed during an UI request.
* The UI request is a nice example to show how to schedule UI actions for sequential execution
*/

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>


//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  int req_id = 0;

  ~plugin_ctx_t()
  {
    if ( req_id != 0 && cancel_exec_request(req_id) )
      msg("Cancelled unexecuted ui_request\n");
  }

  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  class msg_req_t: public ui_request_t
  {
    const char *_msg;
  public:
    msg_req_t(const char *mesg): _msg(qstrdup(mesg)) {}
    ~msg_req_t() { qfree((void *)_msg); }
    virtual bool idaapi run() override
    {
      msg("%s", _msg);
      return false;
    }
  };

  class msgs_req_t: public ui_request_t
  {
    int count;
  public:
    msgs_req_t(int cnt): count(cnt) {}
    virtual bool idaapi run() override
    {
      msg("%d\n", count);
      return --count != 0;
    }
  };

  req_id = execute_ui_requests(
    new msg_req_t("print "),
    new msg_req_t("3 countdown "),
    new msg_req_t("mesages:\n"),
    new msgs_req_t(3),
    nullptr);
  return true;
}


//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "This is a sample ui_requests plugin.",
                        // long comment about the plugin
  "A sample ui_requests and process_ui_commands plugin",
                        // multiline help about the plugin
  "UI requests demo",   // the preferred short name of the plugin
  "Shift-F8"            // the preferred hotkey to run the plugin
};
