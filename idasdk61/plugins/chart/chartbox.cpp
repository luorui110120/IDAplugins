/*
 *  This is a VCL sample plugin module
 *  It demonstrates how to use VCL components in the plugins
 *
 */

//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
//---------------------------------------------------------------------------
#include "chartbox.h"

#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>

#pragma package(smart_init)
#pragma resource "*.dfm"

//---------------------------------------------------------------------------
TChatForm *Form1 = NULL;
//---------------------------------------------------------------------------
__fastcall TChatForm::TChatForm(TComponent* Owner)
        : TForm(Owner)
{
}

//---------------------------------------------------------------------------
// Redraw the chart
void __fastcall TChatForm::RefreshChart(TObject *Sender)
{
  ea_t ea1, ea2;
  // check the selection
  if ( callui(ui_readsel, &ea1, &ea2).cnd )
  {
    char buf[MAXSTR];
    qsnprintf(buf, sizeof(buf), "0x%a", ea1); Edit1->Text = buf;
    qsnprintf(buf, sizeof(buf), "0x%a", ea2); Edit2->Text = buf;
  }
  // get the starting and ending addresses
  char err[MAXSTR];
  ea_t here = get_screen_ea();
  if ( !calcexpr_long(here, Edit1->Text.c_str(), &ea1, err, sizeof(err)) )
  {
    warning("%s", err);
    BringToFront();
    return;
  }
  if ( !calcexpr_long(here, Edit2->Text.c_str(), &ea2, err, sizeof(err)) )
  {
    warning("%s", err);
    BringToFront();
    return;
  }
  // fill the data
  show_wait_box("HIDECANCEL\nGenerating the graph");
  ch->Series[0]->Clear();
  while ( ea1 < ea2 )
  {
    char label[MAXSTR];
    ea2str(ea1, label, sizeof(label));  // generation of the label text takes time, you may want to remove it
    ch->Series[0]->AddXY(ea1, get_byte(ea1), label, TColor(clTeeColor));
    ea1 = next_not_tail(ea1);
  }
  hide_wait_box();
}

//---------------------------------------------------------------------------
void __fastcall TChatForm::Button1Click(TObject *Sender)
{
  Visible = false;
}

//---------------------------------------------------------------------------
void __fastcall TChatForm::FormActivate(TObject *Sender)
{
  // disable text input hotkeys
  enable_input_hotkeys(false);
}

//---------------------------------------------------------------------------
void __fastcall TChatForm::FormDeactivate(TObject *Sender)
{
  // turn hotkeys back on
  enable_input_hotkeys(true);
}

//--------------------------------------------------------------------------
// BEGIN OF CODE COMMON TO ALL IDA PLUGINS USING VCL

// Saved dll original global variables
// We'd rather use the gui interface variables
static TApplication *oapp = NULL;
static TScreen *oscreen   = NULL;
static TMouse *omouse     = NULL;

static int InitializePlugin(void)
{
  TApplication *kapp;
  TScreen *kscreen;
  TMouse *kmouse;
  size_t size = getvcl(&kapp, &kscreen, &kmouse);
  if ( size != 0 )              // GUI version is running
  {
    if ( size != sizeof(TApplication) + sizeof(TScreen) + sizeof(TMouse) )
    {
      msg("VCL version mismatch, the chart plugin is skipped...\n");
      return PLUGIN_SKIP;
    }
    // use the globals from the main user interface
    oapp    = Application; Application = kapp;
    oscreen = Screen;      Screen      = kscreen;
    omouse  = Mouse;       Mouse       = kmouse;
  }
  else                          // TXT version is running
  {                             // Use globals from DLL
    Application->Initialize();
  }
  return PLUGIN_KEEP;
}

static void TerminatePlugin(void)
{
  if ( oapp != NULL )
  {
    Application = oapp;
    Screen      = oscreen;
    Mouse       = omouse;
  }
}

// END OF CODE COMMON TO ALL IDA PLUGINS USING VCL

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLUGIN_SKIP, IDA won't load it again.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory.
//
int idaapi init(void)
{
  // Don't use this plugin for object files
  // This check is just to demonstrate that you may desactive plugin for
  // some file types
  if ( inf.filetype == f_OMF ) return PLUGIN_SKIP;
  // Don't work in text version
  if ( callui(ui_get_hwnd).vptr == NULL ) return PLUGIN_SKIP;
  return InitializePlugin();
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.

void idaapi term(void)
{
  // delete all forms
  delete Form1;
  Form1 = NULL;
  // restore the dll global variables
  TerminatePlugin();
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void idaapi run(int arg)
{
  try
  {
    // We have to create the forms ourselves
    // This could be done in the init() function too
    if ( Form1 == NULL )
      Application->CreateForm(__classid(TChatForm), &Form1);
    Form1->RefreshChart(NULL);
    Form1->Visible = true;
  }
  catch (Exception &exception)
  {
    Application->ShowException(&exception);
  }
}

//--------------------------------------------------------------------------
char comment[] = "Chart builder";

char help[] =
        "Chart builder module\n"
        "\n"
        "This module shows you how to use CBuilder to create plugin modules.\n"
        "\n"
        "It draw charts using the chart component\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Sample chart builder";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t __declspec(dllexport) PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};


//---------------------------------------------------------------------------

