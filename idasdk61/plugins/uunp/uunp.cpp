// Universal Unpacker based on IDA debugger 1.0
// Unpacks PE files

// The algorithm of this plugin is:

//     1. start the process until the entry point of the packed program
//     2. add a breakpoint at kernel32.GetProcAddress
//     3. resume the execution and wait until the packer calls GetProcAddress
//        if the function name passed to GetProcAddress is not in the ignore-list,
//        then switch to the trace mode
//        A call to GetProcAddress() most likely means that the program has been
//        unpacked in the memory and now it setting up its import table
//     4. trace the program in the single step mode until we jump to
//        the area with the original entry point.
//     5. as soon as the current ip belongs OEP area, suspend the execution and
//        inform the user
//
//  So, in short, we allow the unpacker to do its job full speed until
//  it starts to setup the import table. At this moment we switch to the single
//  step mode and try to find the original entry point.
//
//  While this algorithm works with UPX, aspack, and several other packers,
//  it might fail and execution of the packed program might go out of control.
//  So please use this plugin with precaution.
//
//  Ilfak Guilfanov, Yury Haron

#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <name.hpp>
#include "uunp.hpp"

//--------------------------------------------------------------------------
ea_t bp_gpa = BADADDR;  // address of GetProcAddress()
area_t curmod;       // current module area
static bool wait_box_visible = false;
static area_t oep_area; // original entry point area
static char resfile[QMAXPATH]; // resource file name
static ea_t an_imported_func = BADADDR; // an imported function
static bool success = false;
static bool is_9x = false;
static ea_t bpt_ea = BADADDR;     // our bpt address

//--------------------------------------------------------------------------
inline bool my_add_bpt(ea_t ea)
{
  bpt_ea = ea;
  return add_bpt(ea);
}

//--------------------------------------------------------------------------
inline bool my_del_bpt(ea_t ea)
{
  bpt_ea = BADADDR;
  return del_bpt(ea);
}

//---------------------------------------------------------------------------
inline void _hide_wait_box()
{
  if ( wait_box_visible )
  {
    wait_box_visible = false;
    hide_wait_box();
  }
}

//--------------------------------------------------------------------------
inline void set_wait_box(const char *msg)
{
  if ( wait_box_visible )
  {
    replace_wait_box("HIDECANCEL\n%s", msg);
  }
  else
  {
    wait_box_visible = true;
    show_wait_box("HIDECANCEL\n%s", msg);
  }
}

//--------------------------------------------------------------------------
static void move_entry(ea_t rstart)
{
  // remove old start
  set_name(inf.beginEA, "");

  // patch inf struct
  inf.beginEA = rstart;
  inf.startIP = rstart;

  // add new entry point
  add_entry(rstart, rstart, "start", true);
  success = true;

  segment_t *ps = getseg(rstart);
  if ( ps != NULL )
  {
    ps->set_loader_segm(true);
    ps->update();
  }
}

//--------------------------------------------------------------------------
// Unpacker might use some Win32 functions to perform their function
// This function verifies whether we must switch to the trace mode
// or continue to wait for GetProcAddress() of some other interesting function
static bool ignore_win32_api(const char *name)
{
  if ( strcmp(name, "VirtualAlloc") == 0 )
    return true;

  if ( strcmp(name, "VirtualFree") == 0 )
    return true;

  return false;
}

//--------------------------------------------------------------------------
inline bool is_library_entry(ea_t ea)
{
  return !curmod.contains(ea);
}

//--------------------------------------------------------------------------
static bool find_module(ea_t ea, module_info_t *mi)
{
  bool ok;
  for ( ok=get_first_module(mi); ok; ok=get_next_module(mi) )
  {
    if ( area_t(mi->base, mi->base+mi->size).contains(ea) )
      break;
  }
  return ok;
}

//--------------------------------------------------------------------------
static bool create_idata_segm(const area_t &impdir)
{
  segment_t ns;
  segment_t *s = getseg(impdir.startEA);
  if ( s != NULL )
    ns = *s;
  else
    ns.sel = setup_selector(0);

  ns.startEA = impdir.startEA;
  ns.endEA   = impdir.endEA;
  ns.type    = SEG_XTRN;
  ns.set_loader_segm(true);
  bool ok = add_segm_ex(&ns, ".idata", "XTRN", ADDSEG_NOSREG) != 0;
  if ( !ok )
    warning("Can not create the import segment");

  return ok;
}

//--------------------------------------------------------------------------
static bool find_impdir(area_t *impdir)
{
  impdir->startEA = impdir->endEA = 0;

  uint32 ea32 = uint32(an_imported_func);
  for ( ea_t pos = curmod.startEA;
        pos <= curmod.endEA
        && (pos = bin_search(pos, curmod.endEA, (uchar *)&ea32, NULL, 4, BIN_SEARCH_FORWARD,
                             BIN_SEARCH_NOBREAK|BIN_SEARCH_CASE)) != BADADDR;
        pos += sizeof(DWORD) )
  {
    // skip unaligned matches
    if ( (pos & 3) != 0 )
      continue;

    // cool, we found a pointer to an imported function
    // now try to determine the impdir bounds
    ea_t bounds[2] = {pos, pos};

    for ( int k=0; k < 2; k++ )
    {
      ea_t ea = pos;
      while ( true )
      {
        if ( k == 1 )
          ea += 4;
        else
          ea -= 4;

        ea_t func = is_9x ? win9x_find_thunk(ea) : get_long(ea);
        if ( func == 0 )
          continue;

        if ( !isEnabled(func) )
          break;

        if ( curmod.contains(func) )
          break;

        module_info_t mi;
        if ( !find_module(func, &mi) )
          break;

        bounds[k] = ea;
      }
    }

    bounds[1] += 4;

    asize_t bsize = bounds[1] - bounds[0];
    if ( bsize > impdir->size() )
      *impdir = area_t(bounds[0], bounds[1]);
  }
  return impdir->startEA != 0;
}

//--------------------------------------------------------------------------
static void create_impdir(const area_t &impdir)
{
  // now rename all entries in impdir
  do_unknown_range(impdir.startEA, impdir.size(), DOUNK_EXPAND);
  create_idata_segm(impdir);

  char dll[MAXSTR];
  char buf[MAXSTR];
  module_info_t mi;
  mi.base = BADADDR;
  mi.size = 0;
  size_t len = 0;
  for ( ea_t ea=impdir.startEA; ea < impdir.endEA; ea += 4 )
  {
    doDwrd(ea, 4);
    ea_t func = is_9x ? win9x_find_thunk(ea) : get_long(ea);
    if ( !get_true_name(BADADDR, func, buf, sizeof(buf)) )
      continue;

    if ( !area_t(mi.base, mi.base+mi.size).contains(func) )
    {
      find_module(func, &mi);
      qstrncpy(dll, qbasename(mi.name), sizeof(dll));
      char *ptr = strrchr(dll, '.');
      if ( ptr != NULL )
        *ptr = '\0';
      len = strlen(dll);
    }
    const char *name = buf;
    if ( strnicmp(dll, buf, len) == 0 && buf[len] == '_' )
      name += len + 1;
    if ( !do_name_anyway(ea, name) )
      msg("%a: can not rename to imported name '%s'\n", ea, name);
  }
}

//--------------------------------------------------------------------------
static void create_impdir(void)
{
  // refresh dll entry point names
  dbg->stopped_at_debug_event(true);

  // refresh memory configuration
  invalidate_dbgmem_config();

  // found impdir?
  area_t impdir;
  if ( !find_impdir(&impdir) )
    return;
  msg("Uunp: Import directory bounds %a..%a\n", impdir.startEA, impdir.endEA);
  create_impdir(impdir);
}

//--------------------------------------------------------------------------
static void tell_about_failure(void)
{
  warning("The plugin failed to unpack the program, sorry.\n"
          "If you want to improve it, the source code is in the SDK!");
}

//--------------------------------------------------------------------------
static int idaapi callback(
    void * /*user_data*/,
    int notification_code,
    va_list va)
{
  static int stage = 0;
  static bool is_dll;
  static char needed_file[QMAXPATH];

  switch ( notification_code )
  {
    case dbg_process_start:
    case dbg_process_attach:
      get_input_file_path(needed_file, sizeof(needed_file));
      // no break
    case dbg_library_load:
      if ( stage == 0 )
      {
        const debug_event_t *pev = va_arg(va, const debug_event_t *);
        if ( stricmp(pev->modinfo.name, needed_file) != 0 )
          break;
        if ( notification_code == dbg_library_load )
          is_dll = true;
        // remember the current module bounds
        if ( pev->modinfo.rebase_to != BADADDR )
          curmod.startEA = pev->modinfo.rebase_to;
        else
          curmod.startEA = pev->modinfo.base;
        curmod.endEA = curmod.startEA + pev->modinfo.size;
        deb(IDA_DEBUG_PLUGIN, "UUNP: module space %a-%a\n", curmod.startEA, curmod.endEA);
        ++stage;
      }
      break;

    case dbg_library_unload:
      if ( stage != 0 && is_dll )
      {
        const debug_event_t *pev = va_arg(va, const debug_event_t *);
        if ( curmod.startEA == pev->modinfo.base
          || curmod.startEA == pev->modinfo.rebase_to )
        {
          deb(IDA_DEBUG_PLUGIN, "UUNP: unload unpacked module\n");
          if ( stage > 2 )
            enable_step_trace(false);
          stage = 0;
          curmod.startEA = 0;
          curmod.endEA = 0;
          _hide_wait_box();
        }
      }
      break;

    case dbg_run_to:   // Parameters: const debug_event_t *event
      dbg->stopped_at_debug_event(true);
      bp_gpa = get_name_ea(BADADDR, "kernel32_GetProcAddress");
#ifndef __X64__
      if( (LONG)GetVersion() < 0 )  // win9x mode -- use thunk's
      {
        is_9x = true;
        win9x_resolve_gpa_thunk();
      }
#endif
      if ( bp_gpa == BADADDR )
      {
        bring_debugger_to_front();
        warning("Sorry, could not find kernel32.GetProcAddress");
FORCE_STOP:
        stage = 4;  // last stage
        clear_requests_queue();
        request_exit_process();
        run_requests();
        break;
      }
      else if( !my_add_bpt(bp_gpa) )
      {
        bring_debugger_to_front();
        warning("Sorry, can not set bpt to kernel32.GetProcAddress");
        goto FORCE_STOP;
      }
      else
      {
        ++stage;
        set_wait_box("Waiting for a call to GetProcAddress()");
      }
      continue_process();
      break;

    case dbg_bpt:      // A user defined breakpoint was reached.
                       // Parameters: thid_t tid
                       //             ea_t        breakpoint_ea
                       //             int        *warn = -1
                       //             Return (in *warn):
                       //              -1 - to display a breakpoint warning dialog
                       //                   if the process is suspended.
                       //               0 - to never display a breakpoint warning dialog.
                       //               1 - to always display a breakpoint warning dialog.
      {
        /*thid_t tid =*/ va_arg(va, thid_t);
        ea_t ea   = va_arg(va, ea_t);
        //int *warn = va_arg(va, int*);
        if ( stage == 2 )
        {
          if ( ea == bp_gpa )
          {
            regval_t rv;
            if ( get_reg_val("esp", &rv) )
            {
              ea_t esp = ea_t(rv.ival);
              invalidate_dbgmem_contents(esp, 1024);
              ea_t gpa_caller = get_long(esp);
              if ( !is_library_entry(gpa_caller) )
              {
                ea_t nameaddr = get_long(esp+8);
                invalidate_dbgmem_contents(nameaddr, 1024);
                char name[MAXSTR];
                size_t len = get_max_ascii_length(nameaddr, ASCSTR_C, true);
                name[0] = '\0';
                get_ascii_contents(nameaddr, len, ASCSTR_C, name, sizeof(name));
                if ( !ignore_win32_api(name) )
                {
                  deb(IDA_DEBUG_PLUGIN, "%a: found a call to GetProcAddress(%s)\n", gpa_caller, name);
                  if ( !my_del_bpt(bp_gpa) || !my_add_bpt(gpa_caller) )
                    error("Can not modify breakpoint");
                }
              }
            }
          }
          else if ( ea == bpt_ea )
          {
            my_del_bpt(ea);
            if ( !is_library_entry(ea) )
            {
              msg("Uunp: reached unpacker code at %a, switching to trace mode\n", ea);
              enable_step_trace(true);
              ++stage;
              uint64 eax;
              if ( get_reg_val("eax", &eax) )
                an_imported_func = ea_t(eax);
              set_wait_box("Waiting for the unpacker to finish");
            }
            else
            {
              warning("%a: bpt in library code", ea); // how can it be?
              my_add_bpt(bp_gpa);
            }
          }
          // not our bpt? skip it
          else
          {
            // hide the wait box to allow others plugins to properly stop
            _hide_wait_box();
            break;
          }
        }
      }
      continue_process();
      break;

    case dbg_trace:    // A step occured (one instruction was executed). This event
                       // notification is only generated if step tracing is enabled.
                       // Parameter:  none
      if ( stage == 3 )
      {
        /*thid_t tid =*/ va_arg(va, thid_t);
        ea_t ip   = va_arg(va, ea_t);

        // ip reached the OEP range?
        if ( oep_area.contains(ip) )
        {
          // stop the trace mode
          enable_step_trace(false);
          msg("Uunp: reached OEP %a\n", ip);
          set_wait_box("Reanalyzing the unpacked code");

          // reanalyze the unpacked code
          do_unknown_range(oep_area.startEA, oep_area.size(), DOUNK_EXPAND);
          auto_make_code(ip); // plan to make code
          noUsed(oep_area.startEA, oep_area.endEA); // plan to reanalyze
          auto_mark_range(oep_area.startEA, oep_area.endEA, AU_FINAL); // plan to analyze
          move_entry(ip); // mark the program's entry point

          _hide_wait_box();

          // inform the user
          bring_debugger_to_front();
          if ( askyn_c(1,
                       "HIDECANCEL\n"
                       "The universal unpacker has finished its work.\n"
                       "Do you want to take a memory snapshot and stop now?\n"
                       "(you can do it yourself if you want)\n") > 0 )
          {
            set_wait_box("Recreating the import table");
            invalidate_dbgmem_config();

            if ( is_9x )
              find_thunked_imports();

            create_impdir();

            set_wait_box("Storing resources to 'resource.res'");
            if ( resfile[0] != '\0' )
              extract_resource(resfile);

            _hide_wait_box();
            if ( take_memory_snapshot(true) )
              goto FORCE_STOP;
          }
          suspend_process();
          unhook_from_notification_point(HT_DBG, callback, NULL);
        }
      }
      break;

    case dbg_process_exit:
      {
        stage = 0;
        // stop the tracing
        _hide_wait_box();
        unhook_from_notification_point(HT_DBG, callback, NULL);
        if ( success )
          jumpto(inf.beginEA, -1);
        else
          tell_about_failure();
      }
      break;

    case dbg_exception:// Parameters: const debug_event_t *event
                       //             int                 *warn = -1
                       //             Return (in *warn):
                       //              -1 - to display an exception warning dialog
                       //                   if the process is suspended.
                       //               0 - to never display an exception warning dialog.
                       //               1 - to always display an exception warning dialog.

    {
//      const debug_event_t *event = va_arg(va, const debug_event_t *);
//      int *warn = va_arg(va, int *);
      // FIXME: handle code which uses SEH to unpack itself
      if ( askyn_c(1,
                   "AUTOHIDE DATABASE\n"
                   "HIDECANCEL\n"
                   "An exception occurred in the program.\n"
                   "UUNP does not support exceptions yet.\n"
                   "The execution has been suspended.\n"
                   "Do you want to continue the unpacking?") <= 0 )
      {
        _hide_wait_box();
        stage = 0;
        enable_step_trace(false); // stop the trace mode
        suspend_process();
      }
      else
      {
        continue_process();
      }
    }
    break;

    case dbg_request_error:
                       // An error occured during the processing of a request.
                       // Parameters: ui_notification_t  failed_command
                       //             dbg_notification_t failed_dbg_notification
      {
        ui_notification_t  failed_cmd = va_arg(va, ui_notification_t);
        dbg_notification_t failed_dbg_notification = va_arg(va, dbg_notification_t);
        _hide_wait_box();
        stage = 0;
        warning("dbg request error: command: %d notification: %d",
                        failed_cmd, failed_dbg_notification);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
// 0 - run uunp interactively
// 1 - run without questions
// 2 - run manual reconstruction
void idaapi run(int arg)
{
  if ( arg == 2 )
  {
    area_t impdir(0, 0);
    ea_t oep;
    oep = get_screen_ea();
    segment_t *s = getseg(oep);
    if ( s != NULL )
    {
      oep_area.startEA = s->startEA;
      oep_area.endEA = s->endEA;
    }
    if ( !AskUsingForm_c(
      "Reconstruction parameters\n"
      "\n"
      "  <~O~riginal entrypoint:N:128:32::>\n"
      "  <Code ~s~tart address:N:128:32::>\n"
      "  <Code ~e~nd address  :N:128:32::>\n"
      "\n"
      "  <IAT s~t~art address:N:128:32::>\n"
      "  <IAT e~n~d address:N:128:32::>\n"
      "\n",
      &oep,
      &oep_area.startEA,
      &oep_area.endEA,
      &impdir.startEA,
      &impdir.endEA) )
    {
      return;
    }
    if ( impdir.startEA == 0 || impdir.endEA == 0 )
    {
      msg("Invalid import address table boundaries");
      return;
    }

    create_impdir(impdir);

    // reanalyze the unpacked code
    do_unknown_range(oep_area.startEA, oep_area.size(), DOUNK_EXPAND);
    auto_make_code(oep);
    noUsed(oep_area.startEA, oep_area.endEA);
    auto_mark_range(oep_area.startEA, oep_area.endEA, AU_FINAL);

    // mark the program's entry point
    move_entry(oep);

    take_memory_snapshot(true);
    return;
  }

  // determine the original entry point area
  for ( segment_t *s = get_first_seg(); s != NULL; s=get_next_seg(s->startEA) )
  {
    if ( s->type != SEG_GRP )
    {
      oep_area = *s;
      break;
    }
  }

  if (    arg == 0
       && askyn_c(0,
              "HIDECANCEL\n"
              "AUTOHIDE REGISTRY\n"
              "Universal PE unpacker\n"
              "\n"
              "IMPORTANT INFORMATION, PLEASE READ CAREFULLY!\n"
              "\n"
              "This plugin will start the program execution and try to suspend it\n"
              "as soon as the packer finishes its work. Since there might be many\n"
              "variations in packers and packing methods, the execution might go out\n"
              "of control. There are many ways how things can go wrong, but since you\n"
              "have the source code of this plugin, you can modify it as you wish.\n"
              "\n"
              "Do you really want to launch the program?\n") <= 0 )
    {
      return;
    }

  success = false;

  set_file_ext(resfile, sizeof(resfile), database_idb, "res");
  if ( arg == 0
    && !AskUsingForm_c(
        "Uunp parameters\n"
        "IDA will suspend the program when the execution reaches\n"
        "the original entry point area. The default values are in\n"
        "this dialog box. Please verify them and correct if you wish.\n"
        "\n"
        "ORIGINAL ENTRY POINT AREA\n"
        "  <~S~tart address:N:128:32::>\n"
        "  <~E~nd address  :N:128:32::>\n"
        "\n"
        "OUTPUT RESOURCE FILE NAME\n"
        "  <~R~esource file:A:256:32::>\n"
        "\n",
        &oep_area.startEA,
        &oep_area.endEA,
        resfile) )
  {
    return;
  }

  if ( !hook_to_notification_point(HT_DBG, callback, NULL) )
  {
    warning("Could not hook to notification point\n");
    return;
  }

  if ( dbg == NULL )
    load_debugger("win32", false);

  // Let's start the debugger
  if ( !run_to(inf.beginEA) )
  {
    warning("Sorry, could not start the process");
    unhook_from_notification_point(HT_DBG, callback, NULL);
  }
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // Our plugin works only for x86 PE executables
  if ( ph.id != PLFM_386 || inf.filetype != f_PE )
    return PLUGIN_SKIP;

  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  // just to be safe
  unhook_from_notification_point(HT_DBG, callback, NULL);
  _hide_wait_box();
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Universal PE unpacker";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  wanted_name,          // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  wanted_name,          // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
