/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//--------------------------------------------------------------------------
int pflag;

static const char *RegNames[] =
  {
                // r0 == 0 always
                // r3 - stack frame pointer
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10","r11","r12","r13","r14","r15",
    "r16","r17","r18","r19","r20","r21","r22","r23",
    "r24","r25","r26","r27","r28","r29","r30","r31",
                // f0,f1 == 0 always
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "f10","f11","f12","f13","f14","f15",
    "f16","f17","f18","f19","f20","f21","f22","f23",
    "f24","f25","f26","f27","f28","f29","f30","f31",
    "fir",      // Fault Instruction Register (read-only)
    "psr",      // Processor Status Register                 Can Modify
                // 0 - BR       Break Read                   only supervisor
                // 1 - BW       Break Write                  only supervisor
                // 2 - CC       Condition Code
                // 3 - LCC      Loop Condition Code
                // 4 - IM       Interrupt Mode               only supervisor
                //                ena/disa external intrs
                //                on INT pin
                // 5 - PIM      Previous Interrupt Mode      only supervisor
                // 6 - U        User Mode                    only supervisor
                //                1 - user mode
                //                0 - supervisor
                // 7 - PU       Previous User Mode           only supervisor
                // 8 - IT       Instruction Trap             only supervisor
                // 9 - IN       Interrupt                    only supervisor
                // 10- IAT      Instruction Access Trap      only supervisor
                // 11- DAT      Data Access Trap             only supervisor
                // 12- FT       Floating Point Trap          only supervisor
                // 13- DS       Delayed Switch               only supervisor
                // 14- DIM      Dual Instruction Mode        only supervisor
                // 15- KNF      Kill Next FP Instruction     only supervisor
                // 16-          Reserved
                // 17-21 SC     Shift Count
                // 22-23 PS     Pixel Size
                //                      00 - 8
                //                      01 - 16
                //                      10 - 32
                //                      11 - undefined
                // 24-31 PM     Pixel Mask
    "dirbase",  // Directory Base Register
                // 0  ATE       Address Translation Enable
                // 1-3 DPS      DRAM Page Size
                //               ignore 12+DPS bits
                // 4  BL        Bus Lock
                // 5  ITI       Cache and TLB Invalidate
                // 6  LB        Late Back-off Mode
                // 7  CS8       Code Size 8-bit
                // 8-9 RB       Replacement Block
                // 10-11 RC     Replacement Control
                // 12-31 DTB    Directory Table Base
    "db",       // Data Breakpoint Register
    "fsr",      // Floating Point Status Register
                // 0   FZ       Flush Zero
                // 1   TI       Trap Inexact
                // 2-3 RM       Rounding Mode
                //                      0 - nearest or even
                //                      1 - down
                //                      2 - up
                //                      3 - chop
                // 4   U        Update Bit
                // 5   FTE      Floating Point Trap Enable
                // 6            Reserved
                // 7   SI       Sticky Inexact
                // 8   SE       Source Exception
                // 9   MU       Multiplier Underflow
                // 10  MO       Multiplier Overflow
                // 11  MI       Multiplier Inexact
                // 12  MA       Multiplier Add-One
                // 13  AU       Adder Underflow
                // 14  AO       Adder Overflow
                // 15  AI       Adder Inexact
                // 16  AA       Adder Add-One
                // 17-21 RR     Result Register
                // 22-24 AE     Adder Exponent
                // 25-26 LRP    Load Pipe Result Precision
                // 27  IRP      Integer (Graphics) Pipe Result Precision
                // 28  MRP      Multiplier Pipe Result Precision
                // 29  ARP      Adder Pipe Result Precision
                // 30           Reserved
                // 31           Reserved
    "epsr",     // Extended Processor Status Register
                // 0-7          Processor Type
                //               = 2 for i860 XP
                // 8-12         Stepping Number
                // 13 IL        InterLock
                // 14 WP        Write Protect
                // 15 PEF       Parity Error Flag
                // 16 BEF       Bus Error Flag
                // 17 INT       Interrupt
                // 18-21 DCS    Data Cache Size = 2**(12+DCS)
                // 22 PBM       Page-Table Bit Mode
                // 23 BE        Big Endian
                //               0 - little endian
                //               1 - big endian
                // 24 OF        Overflow Flag
                // 25 BS        BEF or PEF In Supervisor Mode
                // 26 DI        Trap On Delayed Instruction
                // 27 TAI       Trap On AutoIncrement Instruction
                // 28 PT        Trap On Pipeline Use
                // 29 PI        Pipeline Instruction
                // 30 SO        Strong Ordering
                // 31           Reserved
    "bear",     // Bus Error Address Register (read-only)
    "ccr",      // Concurrency Control Register
                // 0-1          Reserved
                // 2            Detached Only
                // 3            CCU on
                // 4-11         Reserved
                // 12           Zero
                // 13-31        CCUBASE
    "p0",       // Privileged Register 0 (any purpose)
    "p1",       // Privileged Register 1 (any purpose)
    "p2",       // Privileged Register 2 (any purpose)
    "p3",       // Privileged Register 3 (any purpose)
    "cs","ds"
  };

//----------------------------------------------------------------------
static int notify(processor_t::idp_notify msgid, ...)
{
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch ( msgid )
  {
    case processor_t::newprc:
      {
        int procnum = va_arg(va, int);
        pflag = procnum ? _PT_860XP : _PT_860XR;
      }
      break;

    default:
      break;
  }
  va_end(va);

  return(1);
}

//-----------------------------------------------------------------------
//      aIntel860,
//      Generic for Intel 860
//-----------------------------------------------------------------------
static asm_t i860 =
{
  AS_COLON | ASH_HEXF3,
  0,
  "Generic for Intel 860",
  0,
  NULL,
  NULL,
  "org",
  NULL,

  "//",         // comment string
  '\"',         // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".byte",      // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  "[#d] #v",    // arrays (#h,#d,#v,#s(...)
  ".byte [%s]", // uninited arrays
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

asm_t *i860asms[] = { &i860, NULL };
//-----------------------------------------------------------------------
static const char *shnames[] =
{
  "860xr",
  "860xp",
  NULL
};

static const char *lnames[] =
{
  "Intel 860 XR",
  "Intel 860 XP",
  NULL
};

//--------------------------------------------------------------------------
static bytes_t retcodes[] =
{
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      Intel 860XP processor definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,
  PLFM_I860,            // id
  PR_USE32,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,
  lnames,

  i860asms,

  notify,

  i860_header,
  i860_footer,

  i860_segstart,
  std_gen_segm_footer,

  NULL,

  i860_ana,
  i860_emu,

  i860_out,
  i860_outop,
  intel_data,
  NULL,                 // compare operands
  NULL,                 // can have type

  R_vds+1,                      // Number of registers
  RegNames,                     // Regsiter names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,                         // Register descriptions
  NULL,                         // Pointer to CPU registers

  R_vcs,R_vds,
  0,                            // size of a segment register
  R_vcs,R_vds,

  NULL,                         // No known code start sequences
  retcodes,

  0,I860_last,
  Instructions
};
