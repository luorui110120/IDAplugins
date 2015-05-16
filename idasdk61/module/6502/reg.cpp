/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

//--------------------------------------------------------------------------
static const char * RegNames[] =
{
  "A","X","Y","cs","ds"
};

//----------------------------------------------------------------------
int is_cmos = 0;

static int notify(processor_t::idp_notify msgid, ...) // Various messages:
{
  va_list va;
  va_start(va, msgid);

// A well behaved processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch ( msgid )
  {
    case processor_t::newprc:
      is_cmos = va_arg(va, int);
      break;
    case processor_t::newseg:
      {                  // default DS is equal to CS
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[rVds-ph.regFirstSreg] = sptr->sel;
      }
      break;
    default:
      break;
  }
  va_end(va);

  return(1);
}

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *ps_headers[] = {
".code",
NULL };

static asm_t pseudosam = {
  AS_COLON | ASH_HEXF1 | AS_N2CHR | AS_NOXRF,
  UAS_SELSG,
  "PseudoSam by PseudoCode",
  0,
  ps_headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  ".equ",       // equ
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


//-----------------------------------------------------------------------
//      SVENSON ELECTRONICS 6502/65C02 ASSEMBLER - V.1.0 - MAY, 1988
//-----------------------------------------------------------------------
static asm_t svasm = {
  AS_COLON | ASH_HEXF4,
  UAS_NOSEG,
  "SVENSON ELECTRONICS 6502/65C02 ASSEMBLER - V.1.0 - MAY, 1988",
  0,
  NULL,         // headers
  NULL,
  "* = ",
  ".END",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "\\'",        // special symbols in char and string constants

  ".BYTE",      // ascii string directive
  ".BYTE",      // byte directive
  ".WORD",      // word directive
};

//-----------------------------------------------------------------------
//      TASM assembler definiton
//-----------------------------------------------------------------------
static asm_t tasm = {
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_NOSEG,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  NULL,         // headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",
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
  NULL,     // mod
  "and",    // and
  "or",     // or
  NULL,    // xor
  "not",    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};


//-----------------------------------------------------------------------
//      Avocet assembler definiton
//-----------------------------------------------------------------------
static asm_t avocet = {
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_NOSEG,
  "Avocet Systems 2500AD 6502 Assembler",
  0,
  NULL,         // headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".fcc",       // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".ds %s",     // uninited arrays
};

static asm_t *asms[] = { &svasm, &tasm, &pseudosam, &avocet, NULL };
//-----------------------------------------------------------------------
static const char *shnames[] = { "M6502", "M65C02", NULL };
static const char *lnames[] = { "MOS Technology 6502", "MOS Technology 65C02", NULL };

//--------------------------------------------------------------------------
static uchar retcode_1[] = { 0x60 };
static uchar retcode_2[] = { 0x40 };

static bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,// version
  PLFM_6502,            // id
  PR_SEGS|PR_SEGTRANS,  // flags
  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  std_gen_segm_footer,

  NULL,                 // assumes,

  ana,
  emu,

  out,
  outop,
  intel_data,
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Register names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,                         // Register descriptions
  NULL,                         // Pointer to CPU registers

  rVcs,                         // first
  rVds,                         // last
  0,                            // size of a segment register
  rVcs,rVds,

  NULL,                         // No known code start sequences
  retcodes,

  0,M65_last,
  Instructions
};
