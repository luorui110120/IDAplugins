/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _AUTO_HPP
#define _AUTO_HPP
#include <ida.hpp>
#pragma pack(push, 1)

//
//      This file contains functions that work with the autoanalyzer
//      queue. The autoanalyzer works when IDA is not busy processing
//      the user keystrokes.
//      The autoanalyzer has several queues. Each queue has its priority.
//      A queue contains addresses or address ranges.
//      The addresses are kept sorted by their values.
//      The analyzer will process all addresses from the first queue, then
//      switch to the second queue and so on.
//      There are no limitations on the size of the queues.
//      The analyzer stops when all queues are empty.
//
//      Also this file contains functions that deal with the IDA status
//      indicator and the autoanalysis indicator.
//      You may use these functions to change the indicator value.
//

// Names and priorities of the analyzer queues

typedef int atype_t;
const atype_t           // priority,  description
  AU_NONE = 00,         //    placeholder, not used
  AU_UNK  = 10,         //  0 convert to unexplored
  AU_CODE = 20,         //  1 convert to instruction
  AU_WEAK = 25,         //  2 convert to instruction (ida decision)
  AU_PROC = 30,         //  3 convert to procedure start
  AU_TAIL = 35,         //  4 add a procedure tail
  AU_TRSP = 38,         //  5 trace stack pointer (not used yet)
  AU_USED = 40,         //  6 reanalyze
  AU_TYPE = 50,         //  7 apply type information
  AU_LIBF = 60,         //  8 apply signature to address
  AU_LBF2 = 70,         //  9 the same, second pass
  AU_LBF3 = 80,         // 10 the same, third pass
  AU_CHLB = 90,         // 11 load signature file (file name is kept separately)
  AU_FINAL=200;         // 12 final pass


// IDA status indicator has the following states:

typedef int idastate_t;
const idastate_t
                        //                      meaning
  st_Ready  = 0,        // READY                IDA is doing nothing
  st_Think  = 1,        // THINKING             Autoanalysis on, the user may
                        //                      press keys
  st_Waiting= 2,        // WAITING              Waiting for the user input
  st_Work   = 3;        // BUSY                 IDA is busy


// Enable/disable autoanalyzer. If not set, autoanalyzer will not work.

idaman int ida_export_data autoEnabled;


// Current state of autoanalyzer. Should be used from IDP modules.
// Valid values: AU_CODE - first pass, AU_USED - second pass

idaman atype_t ida_export_data auto_state;


// Structure to hold the autoanalysis indicator contents
struct auto_display_t
{
  atype_t type;
  ea_t ea;
  idastate_t state;
};

idaman auto_display_t ida_export_data auto_display;

// Change autoanalysis indicator value
//      ea - linear address being analyzed
//      type - autoanalysis type

inline void showAuto(ea_t ea, atype_t type=AU_NONE)
{
  auto_display.type = type;
  auto_display.ea = ea;
}


// Show an address on the autoanalysis indicator
//      ea - linear address to display
// The address is displayed in the form " @:12345678"

inline void showAddr(ea_t ea) { showAuto(ea); }


// Change IDA status indicator value
//      st - new indicator status
// returns old indicator status

inline idastate_t setStat(idastate_t st)
{
  idastate_t old = auto_display.state;
  auto_display.state = st;
  return old;
}


// Is it allowed to create stack variables automatically?
// (this function should be used by IDP modules before creating stack vars)

inline bool may_create_stkvars(void)
{
  return should_create_stkvars() && auto_state == AU_USED;
}


// Is it allowed to trace stack pointer automatically?
// (this function should be used by IDP modules before tracing sp)

inline bool may_trace_sp(void)
{
  return should_trace_sp() && (auto_state == AU_USED || auto_state == AU_TRSP);
}


// Put range of addresses into a queue.
// 'start' may be higher than 'end', the kernel will swap them in this case.
// 'end' doesn't belong to the range.

idaman void ida_export auto_mark_range(ea_t start,ea_t end,atype_t type);


// Put single address into a queue. Queues keep addresses sorted.

inline void autoMark(ea_t ea, atype_t type)
{
  if ( ea != BADADDR )
    auto_mark_range(ea, ea+1, type);
}


// Remove range of addresses from a queue.
// 'start' may be higher than 'end', the kernel will swap them in this case.
// 'end' doesn't belong to the range.

idaman void ida_export autoUnmark(ea_t start,ea_t end,atype_t type);


// Convenience functions

inline void noUsed(ea_t ea)                    // plan to reanalysis
  { autoMark(ea,AU_USED); }
inline void noUsed(ea_t sEA,ea_t eEA)          // plan to reanalysis
  { auto_mark_range(sEA,eEA,AU_USED); }
inline void auto_make_code(ea_t ea)            // plan to make code
  { autoMark(ea,AU_CODE); }
inline void auto_make_proc(ea_t ea)            // plan to make code&function
  { auto_make_code(ea); autoMark(ea,AU_PROC); }

void queue_weak_code(ea_t ea);


// Plan to reanalyze callers of the specified address.
// This function will add to AU_USED queue all instructions that
// call (not jump to) the specified address.
//      ea    - linear address of callee
//      noret - !=0: the callee doesn't return, mark to undefine subsequent
//                   instructions in the caller
//              0: do nothing

idaman void ida_export reanalyze_callers(ea_t ea, bool noret);


// process all autorequests with the given type
void auto_process_all(ea_t low, ea_t high, atype_t type);


// Plan to apply the callee's type to the calling point

idaman void ida_export auto_apply_type(ea_t caller, ea_t callee);


// Analyze the specified area.
// Try to create instructions where possible.
// Make the final pass over the specified area.
// This function doesn't return until the area is analyzed.
// Returns: 1 - ok, 0 - Ctrl-Break was pressed

idaman int ida_export analyze_area(ea_t sEA,ea_t eEA);


// Is 'ea' present in AU_CODE queue?
// (i.e. is it planned to be converted to an instruction?)
// if LAZY, then return false if the analysis queue is too big (>10000elements)

bool is_planned_ea(ea_t ea);


// Get next address present in the AU_CODE queue.
// (i.e. the next address planned to be converted to an instruction)
// if LAZY, then return BADADDR if the analysis queue is too big (>10000elements)
// Returns BADADDR if no such address exist.

ea_t get_next_planned_ea(ea_t ea);


// Remove address from AU_CODE queue.
// (i.e. cancel conversion to an instruction)
// You may specify any address as 'ea'.

void autoDelCode(ea_t ea);


// Process enerything in the queues and return true.
// Return false if Ctrl-Break was pressed.

idaman bool ida_export autoWait(void);


// Remove an address range (ea1..ea2) from queues CODE, PROC, USED
// To remove an address range from other queues use autoUnmark() function
// 'ea1' may be higher than 'ea2', the kernel will swap them in this case.
// 'ea2' doesn't belong to the range.

idaman void ida_export autoCancel(ea_t ea1,ea_t ea2);


// Are all queues empty?
// (i.e. has autoanalysis finished?)

idaman bool ida_export autoIsOk(void);


// One step of autoanalyzer if 'autoEnabled' != 0
// Return true if some address was removed from queues and was processed.

idaman bool ida_export autoStep(void);


// Peek into a queue 'type' for an address not lower than 'lowEA'
// Do not remove address from the queue.
// Return the address or BADADDR.

ea_t autoPeek(ea_t lowEA, atype_t type);


// Retrieve an address from queues regarding their priority.
// Returns BADADDR if no addresses not lower than 'lowEA' and less than
// 'highEA' are found in the queues.
// Otherwise *type will have queue type.

idaman ea_t ida_export auto_get(ea_t lowEA, ea_t highEA, atype_t *type);


// Initialize analyzer. The kernel initializes it at the start.

void auto_init(void);
void auto_save(void);
void auto_term(void);


// Get two-character queue name to display on the indicator

idaman const char *ida_export autoGetName(atype_t type);


// The address which is being currently analyzed and therefore
// has no outbound xrefs

extern ea_t ea_without_xrefs;


#pragma pack(pop)
#endif  //  _AUTO_HPP
