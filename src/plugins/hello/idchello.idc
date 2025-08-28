#include <idc.idc>

class hello_plugmod_t
{
  run(arg)
  {
    msg("Hello world! (idc)\n");
    return 0;
  }
}

class hello_plugin_t
{
  hello_plugin_t()
  {
    this.flags = PLUGIN_MULTI;
    this.comment = "This is a comment";
    this.help = "This is help";
    this.wanted_name = "Hello IDC plugin";
    this.wanted_hotkey = "Alt-F6";
  }
  init()
  {
    return hello_plugmod_t();
  }
}

static PLUGIN_ENTRY()
{
  return hello_plugin_t();
}
