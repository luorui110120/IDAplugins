#include <idc.idc>

class myplugin_t
{
  myplugin_t()
  {
    this.flags = 0;
    this.comment = "This is a comment";
    this.help = "This is help";
    this.wanted_name = "Sample IDC plugin";
    this.wanted_hotkey = "Alt-F6";
  }

  init()
  {
    Message("%s: init() has been called\n", this.wanted_name);
    return PLUGIN_OK;
  }

  run(arg)
  {
    Warning("%s: run() has been called with %d", this.wanted_name, arg);
  }

  term()
  {
    Message("%s: term() has been called\n", this.wanted_name);
  }
}

static PLUGIN_ENTRY()
{
  return myplugin_t();
}
