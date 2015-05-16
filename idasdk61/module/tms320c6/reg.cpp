/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#include "tms6.hpp"

//--------------------------------------------------------------------------
// B14 - data page pointer
// B15 - stack pointer
static const char *RegNames[] =
  {
        "A0", "A1",  "A2",  "A3",  "A4",  "A5",  "A6",  "A7",
        "A8", "A9", "A10", "A11", "A12", "A13", "A14", "A15",
        "A16", "A17", "A18", "A19", "A20", "A21", "A22", "A23",
        "A24", "A25", "A26", "A27", "A28", "A29", "A30", "A31",
        "B0", "B1",  "B2",  "B3",  "B4",  "B5",  "B6",  "B7",
        "B8", "B9", "B10", "B11", "B12", "B13", "B14", "B15",
        "B16", "B17", "B18", "B19", "B20", "B21", "B22", "B23",
        "B24", "B25", "B26", "B27", "B28", "B29", "B30", "B31",
        "AMR",
        "CSR",
        "IFR",
        "ISR",
        "ICR",
        "IER",
        "ISTP",
        "IRP",
        "NRP",
        "ACR",  // undocumented, info from Jeff Bailey <jeff_bailey@infinitek.com>
        "ADR",  // undocumented, info from Jeff Bailey <jeff_bailey@infinitek.com>
        "PCE1",
        "FADCR",
        "FAUCR",
        "FMCR",
        "TSCL",
        "TSCH",
        "ILC",
        "RILC",
        "REP",
        "DNUM",
        "SSR",
        "GPLYA",
        "GPLYB",
        "GFPGFR",
        "TSR",
        "ITSR",
        "NTSR",
        "ECR",
        "EFR",
        "IERR",
        "CS","DS"
  };

netnode tnode;

//--------------------------------------------------------------------------
static bool idaapi skip_12(ea_t ea)
{
  ea_t target = tnode.altval(ea);
  return target == 1 || target == 2;
}

//--------------------------------------------------------------------------
static int notify(processor_t::idp_notify msgid, ...) { // Various messages:
  va_list va;
  va_start(va, msgid);
  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;
  switch ( msgid ) {
    case processor_t::newfile:
    case processor_t::oldfile:
      tnode.create("$ tms node");
    default:
      break;

    case processor_t::move_segm:// A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from - old segment address
                                //       segment_t - moved segment
      {
        ea_t from    = va_arg(va, ea_t);
        segment_t *s = va_arg(va, segment_t *);
        asize_t size = s->size();
        tnode.altshift(from, s->startEA, size);
        tnode.altadjust(from, s->startEA, size, skip_12);
      }
      break;

  }
  return(1);
}

//-----------------------------------------------------------------------
//           TMS320C6x COFF Assembler
//-----------------------------------------------------------------------
static asm_t dspasm = {
  AS_COLON | ASH_HEXF0 | ASD_DECF0 | ASB_BINF0 | ASO_OCTF5,
  0,
  "TMS320C6x COFF Assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  NULL,         // org
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".string",    // ascii string directive
  ".char",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  NULL,         // no qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  ".set",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".def",       // "public" name keyword
  NULL,         // "weak"   name keyword
  ".ref",       // "extrn"  name keyword
  ".usect",     // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  "<<",    // shl
  ">>",    // shr
  NULL,    // sizeof
};


static asm_t *asms[] = { &dspasm, NULL };
//-----------------------------------------------------------------------
static const char *shnames[] = { "TMS320C6", NULL };
static const char *lnames[] = {
  "Texas Instruments TMS320C62xx",
  NULL
};

//--------------------------------------------------------------------------
static uchar retcode_1[] = { 0x62, 0x63, 0x0C, 0x00 };

static bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_TMSC6,                   // id
  PR_USE32
  | PR_DEFSEG32
  | PR_DELAYED
  | PR_ALIGN_INSN,              // allow align instructions
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  NULL,                 // assumes

  ana,
  emu,

  out,
  outop,
  data,
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(RegNames),    // Number of registers
  RegNames,             // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  TMS6_null,
  TMS6_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 2, 4, 8, 12 },      // char real_width[4];
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize)(func_t *pfn);
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  outspec,              // Generate text representation of an item in a special segment
  TMS6_null,            // Icode of return instruction. It is ok to give any of possible return instructions
  NULL,                 // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
