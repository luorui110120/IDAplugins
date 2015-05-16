#include "sam8.hpp"
#include <entry.hpp>
#include <srarea.hpp>

extern "C" processor_t LPH;


/*
 * Kernel event handler
 *
 * @param msgid Message ID to handle
 * @param ... Variable list of arguments
 * @return 1 on success
 */
static int notify(processor_t::idp_notify msgid, ...) {
  va_list va;
  va_start(va, msgid);

  // do IDA callbacks
  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  // deal with notification codes
  switch ( msgid ) {
  case processor_t::init:
    inf.mf = 1;       // Set big endian mode in the IDA kernel
    break;

  case processor_t::newfile: {
    {
      // create a new segment for code data
      segment_t seg;
      seg.startEA = SAM8_CODESEG_START;
      seg.endEA   = SAM8_CODESEG_START + SAM8_CODESEG_SIZE;
      seg.sel     = allocate_selector(seg.startEA >> 4);
      seg.type    = SEG_NORM;
      add_segm_ex(&seg, "code", NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
    }
    {
      // create a new segment for the external data
      segment_t seg;
      seg.startEA = SAM8_EDATASEG_START;
      seg.endEA   = SAM8_EDATASEG_START + SAM8_EDATASEG_SIZE;
      seg.sel     = allocate_selector(seg.startEA >> 4);
      seg.flags   = SFL_HIDDEN;
      seg.type    = SEG_BSS;
      add_segm_ex(&seg, "emem", NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
    }
    break;
  }

  default:
    break;
  }
  va_end(va);

  // OK
  return(1);
}


//-----------------------------------------------------------------------
// Condition codes
const char *const ccNames[] = {
  "F",
  "LT",
  "LE",
  "ULE",
  "OV",
  "MI",
  "EQ",
  "C",
  "T",
  "GE",
  "GT",
  "UGT",
  "NOV",
  "PL",
  "NE",
  "NC",
};


/************************************************************************/
/* Register names                                                       */
/************************************************************************/
static const char *RegNames[] = {
  "cs","ds"
};


/************************************************************************/
/*                      Samsung Assembler   -   Version 1.42            */
/*              Copyright © 1995,96 M.Y.Chong SAMSUNG ASIA PTE LTD      */
/*                             Semiconductor Division                   */
/************************************************************************/

/************************************************************************/
/* File headers for SAMA assembler                                      */
/************************************************************************/
static const char *sama_headers[] = {
  "",
  "; Filename of DEF file describing the chip in use",
  "CHIP <DEF Filename>",
  "",
  "; External memory EQU definitions",
  "; These will appear here when output using the samaout plugin",
  NULL };


/************************************************************************/
/* Definition of SAMA assembler                                         */
/************************************************************************/
static asm_t sama = {
  AS_COLON,
  0,
  "Samsung Assembler (SAMA) by Samsung Semiconductor Division",
  0,
  (const char**) sama_headers,         // no headers
  NULL,         // no bad instructions
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "+_*/%&|^()<>!+$@#.,\'\"?",    // special symbols in char+string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  NULL,         // uninited arrays
  "equ",        // equ
  NULL,         // seg prefix
  NULL, NULL, NULL,
  NULL,
  "$",
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
  "~",     // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
  0,
};

/************************************************************************/
/* Assemblers supported by this module                                  */
/************************************************************************/
static asm_t *asms[] = { &sama, NULL };


/************************************************************************/
/* Short names of processor                                             */
/************************************************************************/
static const char *shnames[] =
{
  "SAM8",
  NULL
};

/************************************************************************/
/* Long names of processor                                              */
/************************************************************************/
static const char *lnames[] = {
  "Samsung SAM8-based processors",
  NULL
};



//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static uchar retcode_1[] = { 0xAF };
static uchar retcode_2[] = { 0xBF };

static bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { 0, NULL }                            // NULL terminated array
};



//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,// version
  PLFM_SAM8,            // id
  PR_RNAMESOK | PR_BINMEM,          // can use register names for byte names
  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  header,               // generate the disassembly header
  footer,               // generate the disassembly footer

  segstart,             // generate a segment declaration (start of segment)
  std_gen_segm_footer,  // generate a segment footer (end of segment)

  NULL,                 // generate 'assume' directives

  ana,                  // analyze an instruction and fill the 'cmd' structure
  emu,                  // emulate an instruction

  out,                  // generate a text representation of an instruction
  outop,                // generate a text representation of an operand
  out_data,             // generate a text representation of a data item
  NULL,                 // compare operands
  NULL,                 // can an operand have a type?

  qnumber(RegNames),    // Number of registers
  RegNames,             // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0,SAM8_last,
  Instructions
};
