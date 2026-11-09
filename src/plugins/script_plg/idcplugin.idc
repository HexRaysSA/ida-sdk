#include <idc.idc>

class myplugmod_t
{
  myplugmod_t()
  {
    this.wanted_name = "Sample IDC plugin";
  }
  run(arg)
  {
    msg("%s: run() has been called with %d\n", this.wanted_name, arg);
    return (arg % 2) == 0;
  }
  ~myplugmod_t()
  {
    msg("%s: unloaded\n", this.wanted_name);
  }
}

class myplugin_t
{
  myplugin_t()
  {
    this.flags = PLUGIN_MULTI;
    this.comment = "This is a sample IDC plugin";
    this.help = "This is help";
    this.wanted_name = "Sample IDC plugin";
    this.wanted_hotkey = "Alt-F6";
  }

  init()
  {
    msg("%s: init() has been called\n", this.wanted_name);
    return myplugmod_t();
  }

  run(arg)
  {
    msg("%s: ERROR: run() has been called for global object!\n", this.wanted_name);
    return (arg % 2) == 0;
  }

  term()
  {
    msg("%s: ERROR: term() has been called  (should never be called)\n", this.wanted_name);
  }
}

static PLUGIN_ENTRY()
{
  return myplugin_t();
}
