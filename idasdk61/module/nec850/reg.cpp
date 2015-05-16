/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor description structures
 *
 */
#include "necv850.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <loader.hpp>
#include <srarea.hpp>

// program pointers (gp, tp)
static netnode prog_pointers;
#define GP_EA_IDX 1
ea_t g_gp_ea = BADADDR; // global pointer

//------------------------------------------------------------------
const char *idaapi set_idp_options(
  const char *keyword,
  int value_type,
  const void *value)
{
  if ( keyword != NULL )
  {
    if ( strcmp(keyword, "GP_EA") == 0 )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      g_gp_ea = *((uval_t *)value);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }

  static const char form[] =
    "NEC V850x analyzer options\n"
    "\n"
    " <~G~lobal Pointer address:$:16:16::>\n"
    "\n"
    "\n"
    "\n";
  ea_t gp_ea = g_gp_ea;
  if ( AskUsingForm_c(form, &gp_ea) != 0 )
    g_gp_ea = gp_ea;

  return IDPOPT_OK;
}

//----------------------------------------------------------------------
static asm_t nec850_asm =
{
  ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,  // flags
  0,                                // user flags
  "NEC V850 Assembler",             // assembler name
  0,                                // help
  NULL,                             // array of automatically generated header lines
  NULL,                             // array of unsupported instructions
  ".org",                           // org directive
  ".end",                           // end directive
  "--",                             // comment string
  '"',                              // string delimiter
  '\'',                             // char delimiter
  "'\"",                            // special symbols in char and string constants
  ".str",                           // ascii string directive
  ".byte",                          // byte directive
  ".hword",                         // word directive -- actually half a word (16bits)
  ".word",                          // double words -- actually a 32bits word
  NULL,                             // qwords
  NULL,                             // oword  (16 bytes)
  ".float",                         // float
  NULL,                             // no double
  NULL,                             // no tbytes
  NULL,                             // no packreal
  "#d dup(#v)",                     //".db.#s(b,w) #d,#v"
  ".byte (%s) ?",                   // uninited data (reserve space) ;?
  ".set",                           // 'equ' Used if AS_UNEQU is set
  NULL,                             // seg prefix
  NULL,                             // preline for checkarg
  NULL,                             // checkarg_atomprefix
  NULL,                             // checkarg operations
  NULL,                             // XlatAsciiOutput
  "PC",                             // a_curip
  NULL,                             // returns function header line
  NULL,                             // returns function footer line
  ".globl",                         // public
  NULL,                             // weak
  ".extern",                        // extrn
  ".comm",                          // comm
  NULL,                             // get_type_name
  ".align",                         // align
  '(',                              // lbrace
  ')',                              // rbrace
  NULL,                             // mod
  "&",                              // bit-and
  "|",                              // or
  "^",                              // xor
  "!",                              // not
  "<<",                             // shl
  ">>",                             // shr
  NULL,                             // sizeof
  0,                                // flags2
  NULL,                             // cmnt2
  NULL,                             // low8 operation, should contain %s for the operand
  NULL,                             // high8
  NULL,                             // low16
  NULL,                             // high16
  ".include %s",                    // a_include_fmt
  NULL,                             // if a named item is a structure and displayed
  NULL,                             // 3-byte data
  NULL                              // 'rva' keyword for image based offsets
};

static asm_t *asms[] = { &nec850_asm, NULL };

//----------------------------------------------------------------------
static const char *shnames[] =
{
  "V850E1",
  "V850",
  NULL
};

static const char *lnames[] =
{
  "NEC V850E1/ES",
  "NEC V850",
  NULL
};

//----------------------------------------------------------------------
static int idaapi nec850_notify(processor_t::idp_notify msgid, ...)
{
  va_list va;
  va_start(va, msgid);

  // A well behaving processor module should call invoke_callbacks()
  // in his notify() function. If this function returns 0, then
  // the processor module should process the notification itself
  // Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code )
    return code;

  switch ( msgid )
  {
  case processor_t::init:
    inf.mf = 0;
    prog_pointers.create("$ prog pointers");
    break;

  case processor_t::is_sane_insn:
    {
      int no_crefs = va_arg(va, int);
      return nec850_is_sane_insn(no_crefs);
    }

  case processor_t::newprc:
    {
      int procnum = va_arg(va, int);
      is_v850e = procnum == 0;
      break;
    }
  case processor_t::term:
    break;

  // save database
  case processor_t::closebase:
  case processor_t::savebase:
    prog_pointers.altset(GP_EA_IDX, g_gp_ea);
    break;

  // old file loaded
  case processor_t::oldfile:
    g_gp_ea = prog_pointers.altval(GP_EA_IDX);
    break;

  case processor_t::newseg:
    {
      segment_t *s = va_arg(va, segment_t *);
      // Set default value of DS register for all segments
      set_default_dataseg(s->sel);
    }
  // A segment is moved
  //case processor_t::move_segm:
  //  // Fix processor dependent address sensitive information
  //  // args: ea_t from - old segment address
  //  //       segment_t - moved segment
  //  {
  //    ea_t from    = va_arg(va, ea_t);
  //    segment_t *s = va_arg(va, segment_t *);
  //    // adjust gp_ea
  //  }
  //  break;
  default:
    break;
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
//      Registers Definition
//-----------------------------------------------------------------------
const char *RegNames[rLastRegister] =
{
  "r0",
  "r1",
  "r2",
  "sp",
  "gp",
  "r5", // text pointer - tp
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "r16",
  "r17",
  "r18",
  "r19",
  "r20",
  "r21",
  "r22",
  "r23",
  "r24",
  "r25",
  "r26",
  "r27",
  "r28",
  "r29",
  "ep",
  "lp",
  // system registers start here
  "eipc",
  "eipsw",
  "fepc",
  "fepsw",
  "ecr",
  "psw",
  "sr6",
  "sr7",
  "sr8",
  "sr9",
  "sr10",
  "sr11",
  "sr12",
  "sr13",
  "sr14",
  "sr15",
  "sr16",
  "sr17",
  "sr18",
  "sr19",
  "sr20",
  "sr21",
  "sr22",
  "sr23",
  "sr24",
  "sr25",
  "sr26",
  "sr27",
  "sr28",
  "sr29",
  "sr30",
  "sr31",
  //
  "ep", "cs", "ds"
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,     // kernel version
  PLFM_NEC_V850X,            // id
  /*PR_SEGS |*/ PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE, // flags
  8,                         // 8 bits in a byte for code segments
  8,                         // 8 bits in a byte for other segments

  shnames,                   // short processor names
  lnames,                    // long processor names

  asms,                      // assemblers

  nec850_notify,

  nec850_header,             // function to produce start of disassembled text
  nec850_footer,             // function to produce end of disassembled text

  nec850_segstart,           // function to produce start of segment
  nec850_segend,             // function to produce end of segment

  NULL,                      // function to produce assume directives

  nec850_ana,                // Analyze one instruction and fill 'cmd' structure.
  nec850_emu,                // Emulate instruction
  nec850_out,                // Generate text representation of an instruction in 'cmd' structure
  nec850_outop,              // Generate text representation of an instructon operand.
  intel_data,                // Generate text represenation of data items
  NULL,                      // Compare instruction operands.
  NULL,                      // can_have_type
  rLastRegister,             // Number of registers
  RegNames,                  // Regsiter names
  NULL,                      // get abstract register
  0,                         // Number of register files
  NULL,                      // Register file names
  NULL,                      // Register descriptions
  NULL,                      // Pointer to CPU registers

  rVcs/*rVep*/,              // number of first segment register
  rVds/*rVcs*/,              // number of last segment register
  0 /*4*/,                   // size of a segment register
  rVcs,
  rVds,
  NULL,                      // No known code start sequences
  NULL,                      // Array of 'return' instruction opcodes
  NEC850_NULL,
  NEC850_LAST_INSTRUCTION,
  Instructions,
  NULL,                      // isFarJump or Call
  NULL,                      // Translation function for offsets
  0,                         // size of tbyte
  ieee_realcvt,
  {0,7,15,0},                // real width
  nec850_is_switch,          // is this instruction switch
  NULL,                      // generate map-file
  NULL,                      // extract address from a string
  nec850_is_sp_based,        // is_sp_based
  nec850_create_func_frame,  // create_func_frame
  nec850_get_frame_retsize,  // get_frame_retsize
  NULL,                      // gen_stkvar_def
  gen_spcdef,                // out special segments
  0,                         // icode_return
  set_idp_options,           // Set IDP options (set_idp_options)
  NULL,                      // Is alignment instruction?
  NULL,                      // Micro virtual machine description
  0                          // high_fixup_bits
};

//-----------------------------------------------------------------------
