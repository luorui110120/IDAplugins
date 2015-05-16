/*
 *  This plugin demonstrates how to use choosers inside forms.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
// raw data of the png icon (16x16)
static unsigned char icon_data[182] =
{
  0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF,
  0x61, 0x00, 0x00, 0x00, 0x7D, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0x64, 0xC0, 0x0E, 0xFE,
  0xE3, 0x10, 0x67, 0x24, 0x28, 0x00, 0xD2, 0xFC, 0xF3, 0xAF, 0x36, 0x56, 0xDD, 0xEC, 0xCC, 0x57,
  0x31, 0xF4, 0x20, 0x73, 0xC0, 0xB6, 0xE2, 0xD2, 0x8C, 0x66, 0x08, 0x5C, 0x2F, 0x8A, 0x01, 0x84,
  0x34, 0x63, 0x73, 0x09, 0x23, 0xA9, 0x9A, 0xD1, 0x0D, 0x61, 0x44, 0xD7, 0xCC, 0xCF, 0x02, 0x71,
  0xE2, 0xC7, 0x3F, 0xA8, 0x06, 0x62, 0x13, 0x07, 0x19, 0x42, 0x7D, 0x03, 0x48, 0xF5, 0xC6, 0x20,
  0x34, 0x00, 0xE4, 0x57, 0x74, 0xFF, 0xE3, 0x92, 0x83, 0x19, 0xC0, 0x40, 0x8C, 0x21, 0xD8, 0x34,
  0x33, 0x40, 0xA3, 0x91, 0x01, 0x97, 0x21, 0xC8, 0x00, 0x9B, 0x66, 0x38, 0x01, 0x33, 0x00, 0x44,
  0x50, 0x92, 0x94, 0xB1, 0xBA, 0x04, 0x8B, 0x66, 0x9C, 0x99, 0x09, 0xC5, 0x10, 0x1C, 0xE2, 0x18,
  0xEA, 0x01, 0xA3, 0x65, 0x55, 0x0B, 0x33, 0x14, 0x07, 0x63, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
  0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
};
static int icon_id = 0;

//--------------------------------------------------------------------------
// column widths
static const int widths[] = { 40 };

// column headers
static const char *header[] =
{
  "Item",
};
CASSERT(qnumber(widths) == qnumber(header));

//--------------------------------------------------------------------------
static int main_current_index = 1;

//-------------------------------------------------------------------------
// function that generates the list line
static void idaapi aux_choose_getl(void * /*obj*/, uint32 n, char *const *arrptr)
{
  if ( n == 0 ) // generate the column headers
    qstrncpy(arrptr[0], header[0], MAXSTR);
  else
    qsnprintf(arrptr[0], MAXSTR, "Item %d", n);
}

//-------------------------------------------------------------------------
// function that returns number of lines in the list
static uint32 idaapi main_choose_sizer(void * /*obj*/)
{
  return 10;
}

//-------------------------------------------------------------------------
// function that returns number of lines in the list
static uint32 idaapi aux_choose_sizer(void * /*obj*/)
{
  return main_current_index;
}

//-------------------------------------------------------------------------
// function that generates the list line
static void idaapi main_choose_getl(void * /*obj*/,uint32 n, char *const *arrptr)
{
  // generate the column headers
  if ( n == 0 )
    qstrncpy(arrptr[0], header[0], MAXSTR);
  else
    qsnprintf(arrptr[0], MAXSTR, "Option %d", n);
}

//-------------------------------------------------------------------------
static void refresh_selection_edit(form_actions_t & fa)
{
  static char str[MAXSTR], tmp[100];
  static intvec_t array;

  if ( main_current_index == 0 )
    qstrncpy(str, "No selection", sizeof(str));
  else
  {
    qsnprintf(str, sizeof(str), "Main %d", main_current_index);

    fa.get_field_value(4, &array);
    if ( array.size() > 0 )
    {
      qstrncat(str, " - Aux item(s) ", sizeof(str));
      for ( int i = 0; i < array.size() - 1; i++ )
      {
        qsnprintf(tmp, sizeof(tmp), "%d, ", array.at(i));
        qstrncat(str, tmp, sizeof(str));
      }
      qsnprintf(tmp, sizeof(tmp), "%d", array.at(array.size() - 1));
      qstrncat(str, tmp, sizeof(str));
    }
  }

  fa.set_field_value(5, str);
}

//---------------------------------------------------------------------------
static uint32 idaapi chooser_menu_cmd(void * /*obj*/, uint32 /*n*/)
{
  msg("Menu item clicked!\n");
  return 1;
}

//--------------------------------------------------------------------------
static int idaapi modcb(int fid, form_actions_t &fa)
{
  static intvec_t array;
  switch ( fid )
  {
    case -1:
      msg("initializing\n");
      refresh_selection_edit(fa);
      // add an item to the context menu of the main chooser
      // note: the caption "Form with choosers:3" contains the title of the
      //       form followed by a colon delimiter and the field id of the
      //       embedded chooser
      add_chooser_command("Form with choosers:3", "Test", chooser_menu_cmd,
                          -1, icon_id, CHOOSER_POPUP_MENU);
      break;
    case -2:
      msg("terminating\n");
      break;
    // main chooser
    case 3:
      msg("main chooser selection change\n");
      fa.get_field_value(3, &array);
      if ( array.size() > 0 )
        main_current_index = array[0];
      else
        main_current_index = 0;
      // refresh auxiliar chooser
      fa.refresh_field(4);
      refresh_selection_edit(fa);
      break;
    // auxiliar chooser
    case 4:
      refresh_selection_edit(fa);
      break;
    // Aux value text control
    case 5:
      break;
    default:
      msg("unknown id %d\n", fid);
      break;
  }

  return 1;
}

//--------------------------------------------------------------------------
static void idaapi run(int)
{
  static const char form[] =
    "STARTITEM 0\n"
    "Form with choosers\n\n"
    "%/"
    "Select an item in the main chooser:\n"
    "\n"
    "<Main chooser:E3::30::><Auxiliar chooser (multi):E4::30::>\n\n"
    "<Selection:A5:1023:40::>\n"
    "\n";

  static chooser_info_t main_chi =
  {
    sizeof(chooser_info_t),
    CH_NOIDB, // flags (doesn't need an open database)
    0, 0, // width, height
    NULL, //title
    NULL, // obj
    qnumber(header), // columns
    widths,
    icon_id, // icon
    0, // deflt
    NULL, // popup_names
    main_choose_sizer,
    main_choose_getl,
    NULL, // del
    NULL, // ins
    NULL, // update
    NULL, // edit
    NULL, // enter
    NULL, // destroyer
    NULL, // get_icon
    NULL, // select
    NULL // refresh
  };

  chooser_info_t aux_chi = main_chi;
  aux_chi.flags |= CH_MULTI;
  aux_chi.sizer = aux_choose_sizer;
  aux_chi.getl = aux_choose_getl;

  intvec_t main_sel, aux_sel;
  char str[MAXSTR];
  str[0] = '\0';

  // default selection for the main chooser
  main_sel.push_back(main_current_index);

  if ( AskUsingForm_c(form, modcb,
                      &main_chi, &main_sel,
                      &aux_chi, &aux_sel,
                      str) > 0 )
  {
    msg("Selection: %s\n", str);
  }
}

//--------------------------------------------------------------------------
static int idaapi init(void)
{
  icon_id = load_custom_icon(icon_data, sizeof(icon_data), "png");
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
static void idaapi term(void)
{
  free_custom_icon(icon_id);
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,
  init,                  // initialize
  term,                  // terminate. this pointer may be NULL.
  run,                   // invoke plugin
  NULL,                  // long comment about the plugin
  NULL,                  // multiline help about the plugin
  "Forms chooser sample",// the preferred short name of the plugin
  NULL                   // the preferred hotkey to run the plugin
};
