/*
 *  This is a sample plugin module
 *
 *      It demonstrates how to get the the entry point prototypes
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>

struct item_t
{
  int ord;
  ea_t ea;
  qstring decl;
  uint32 argsize;
};

typedef qvector<item_t> entrylist_t;

//--------------------------------------------------------------------------
int idaapi init(void)
{
  if ( get_entry_qty() == 0 )
    return PLUGIN_SKIP;
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
// column widths
static const int widths[] = { CHCOL_DEC|4, CHCOL_HEX|8, CHCOL_HEX|6, 70 };

// column headers
static const char *const header[] =
{
  "Ordinal",
  "Address",
  "ArgSize",
  "Declaration",
};
CASSERT(qnumber(widths) == qnumber(header));

//-------------------------------------------------------------------------
// function that returns number of lines in the list
static uint32 idaapi sizer(void *obj)
{
  entrylist_t &li = *(entrylist_t *)obj;
  return (uint32)li.size();
}

//-------------------------------------------------------------------------
// function that generates the list line
static void idaapi desc(void *obj,uint32 n,char * const *arrptr)
{
  if ( n == 0 ) // generate the column headers
  {
    for ( int i=0; i < qnumber(header); i++ )
      qstrncpy(arrptr[i], header[i], MAXSTR);
    return;
  }
  n--;
  entrylist_t &li = *(entrylist_t *)obj;

  qsnprintf(arrptr[0], MAXSTR, "%d", li[n].ord);
  qsnprintf(arrptr[1], MAXSTR, "%08a", li[n].ea);
  if ( li[n].argsize != 0 )
    qsnprintf(arrptr[2], MAXSTR, "%04x", li[n].argsize);
  qsnprintf(arrptr[3], MAXSTR, "%s", li[n].decl.c_str());
}

//-------------------------------------------------------------------------
// function that is called when the user hits Enter
static void idaapi enter_cb(void *obj,uint32 n)
{
  entrylist_t &li = *(entrylist_t *)obj;
  jumpto(li[n-1].ea);
}

//-------------------------------------------------------------------------
// function that is called when the window is closed
static void idaapi destroy_cb(void *obj)
{
  entrylist_t *li = (entrylist_t *)obj;
  delete li;
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  if ( !autoIsOk()
    && askyn_c(-1, "HIDECANCEL\n"
                   "The autoanalysis has not finished yet.\n"
                   "The result might be incomplete. Do you want to continue?") < 0 )
    return;

  // gather information about the entry points
  entrylist_t *li = new entrylist_t;
  size_t n = get_entry_qty();
  for ( size_t i=0; i < n; i++ )
  {
    asize_t ord = get_entry_ordinal((int)i);
    ea_t ea = get_entry(ord);
    if ( ord == ea )
      continue;
    qtype type, fnames;
    char decl[MAXSTR];
    char true_name[MAXSTR];
    asize_t argsize = 0;
    get_entry_name(ord, true_name, sizeof(true_name));
    if ( get_tinfo(ea, &type, &fnames)
      && print_type_to_one_line(
                decl, sizeof(decl),
                idati,
                type.c_str(),
                true_name,
                NULL,
                fnames.c_str()) == T_NORMAL )
    {
//    found type info -- calc the args size
      func_type_info_t fi;
      int a = build_funcarg_info(idati, type.c_str(), fnames.c_str(), &fi, 0);
      if ( a != 0 )
      {
        for ( int k=0; k < a; k++ )
        {
          const type_t *ptr = fi[k].type.c_str();
          int s1 = (int)get_type_size(idati, ptr);
          s1 = qmax(s1, inf.cc.size_i);
          argsize += s1;
        }
      }
    }
    else if ( get_long_name(BADADDR, ea, decl, sizeof(decl)) != NULL
           && get_true_name(BADADDR, ea, true_name, sizeof(true_name)) != NULL
           && strcmp(decl, true_name) != 0 )
    {
//      found mangled name
    }
    else
    {
//      found nothing, just show the name
      const char *name = get_name(BADADDR, ea, true_name, sizeof(true_name));
      if ( name == NULL )
        continue;
      qstrncpy(decl, name, sizeof(decl));
    }
    if ( argsize == 0 )
    {
      func_t *pfn = get_func(ea);
      if ( pfn != NULL )
        argsize = pfn->argsize;
    }
    item_t x;
    x.ord = (int)ord;
    x.ea = ea;
    x.decl = decl;
    x.argsize = (uint32)argsize;
    li->push_back(x);
  }

  // now open the window
  choose2(false,                // non-modal window
          -1, -1, -1, -1,       // position is determined by Windows
          li,                   // pass the created array
          qnumber(header),      // number of columns
          widths,               // widths of columns
          sizer,                // function that returns number of lines
          desc,                 // function that generates a line
          "Exported functions", // window title
          -1,                   // use the default icon for the window
          0,                    // position the cursor on the first line
          NULL,                 // "kill" callback
          NULL,                 // "new" callback
          NULL,                 // "update" callback
          NULL,                 // "edit" callback
          enter_cb,             // function to call when the user pressed Enter
          destroy_cb,           // function to call when the window is closed
          NULL,                 // use default popup menu items
          NULL);                // use the same icon for all lines
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  NULL,
  run,                  // invoke plugin
  "Generate list of exported function prototypes",
  "Generate list of exported function prototypes",

  "List of exported functions",
  "Ctrl-F11",
};
