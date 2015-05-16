/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"
//----------------------------------------------------------------------
static const char *RegNames[] =
  {
  "R0","R1","R2","R3","R4","R5","SP","PC",
  "AC0", "AC1", "AC2", "AC3", "AC4", "AC5",
  "cs","ds"
  };

//-----------------------------------------------------------------------
#include "chkarg.cpp"

//-----------------------------------------------------------------------
//                   MACRO-11 Macro Assembler
//-----------------------------------------------------------------------
static uchar trans_dec_pc1[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,     // 0000
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,     // 0010
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,     // 0020
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,     // 0030
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,     // 0040
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,     // 0050
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,     // 0060
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,     // 0070
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,     // 0100
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,     // 0110
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,     // 0120
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,     // 0130
    0x9E, 0x80, 0x81, 0x96, 0x84, 0x85, 0x94, 0x83,     // 0140
    0x95, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,     // 0150
    0x8F, 0x9F, 0x90, 0x91, 0x92, 0x93, 0x86, 0x82,     // 0160
    0x9C, 0x9B, 0x87, 0x98, 0x9D, 0x99, 0x97, 0177,     // 0170
    0200, 0201, 0202, 0203, 0204, 0205, 0206, 0207,     // 0200
    0210, 0211, 0212, 0213, 0214, 0215, 0216, 0217,     // 0210
    0220, 0221, 0222, 0223, 0224, 0225, 0226, 0227,     // 0220
    0230, 0231, 0232, 0233, 0234, 0235, 0236, 0237,     // 0230
    0240, 0241, 0242, 0243, 0244, 0245, 0246, 0247,     // 0240
    0250, 0251, 0252, 0253, 0254, 0255, 0256, 0257,     // 0250
    0260, 0261, 0262, 0263, 0264, 0265, 0266, 0267,     // 0260
    0270, 0271, 0272, 0273, 0274, 0275, 0276, 0277,     // 0270
    0140, 0141, 0142, 0143, 0144, 0145, 0146, 0147,     // 0300
    0150, 0151, 0152, 0153, 0154, 0155, 0156, 0157,     // 0310
    0160, 0161, 0162, 0163, 0164, 0165, 0166, 0167,     // 0320
    0170, 0171, 0172, 0173, 0174, 0175, 0176, 0x9A,     // 0330
    0xEE, 0xA0, 0xA1, 0xE6, 0xA4, 0xA5, 0xE4, 0xA3,     // 0340
    0xE5, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,     // 0350
    0xAF, 0xEF, 0xE0, 0xE1, 0xE2, 0xE3, 0xA6, 0xA2,     // 0360
    0xEC, 0xEB, 0xA7, 0xE8, 0xED, 0xE9, 0xE7, 0xEA};    // 0370

static const char *array_macro[] = {
    "",
    ".macro .array of,type,cnt,val",
    ".rept  cnt",
    " type  val",
    ".endr",
    ".endm .array",
    NULL};

static asm_t macro11 = {
  /*AS_UNEQU |*/ AS_COLON | AS_2CHRE | AS_NCHRE | ASH_HEXF5 | ASO_OCTF2 | ASD_DECF2 | AS_NCMAS | AS_ONEDUP | ASB_BINF1 | AS_RELSUP,
  UAS_SECT,
  "Macro-11 Assembler",
  0,
  array_macro,     //header
  NULL,
  ".",        //org
  ".END",

  ";",        // comment string
  '\\',       // string delimiter
  '\'',       // char delimiter
  "\\\200",     // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // no qwords
  NULL,         // oword  (16 bytes)
  ".flt2",
  ".flt4",
  NULL,       // no tbytes
  NULL,       // no packreal
  ".array of #hs cnt=#d val=#v",  // #h - header(.byte,.word)
                                // #d - size of array
                                // #v - value of array elements
  ".blkb  %s",  // uninited data (reserve space)
  "=",
  NULL,      // seg prefix
  chkarg_dispatch_pdp11,  // preline for checkarg
  NULL,                   // FREE (was: checkarg_atomprefix)
  NULL,                   // FREE (was: checkarg operations)
  NULL,      // XlatAsciiOutput
  ".",       // a_curip
  NULL,     //func_header
  NULL,     //func_footer
  ".globl",     // public
  ".weak",      // weak
  ".globl",     // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '<', '>',     // lbrace, rbrace
  NULL,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//--------------------------------------------------------------------------
pdp_ml_t m = { uint32(BADADDR), 0, 0, 0 };
netnode  ovrtrans;

static const char ovrtrans_name[] = "$ pdp-11 overlay translations";

//----------------------------------------------------------------------
// Set IDP-specific options

static const char form[] =
"PDP-11 options\n"
"\n"
"  <Enable ASCII string character translation:C>>\n"
"\n"
"  (the translation table is specified with\n"
"   XlatAsciiOutput variable in IDA.CFG)\n"
"\n"
"\n";

const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  ushort trans;
  if ( keyword == NULL )
  {
    trans = macro11.XlatAsciiOutput != NULL;
    if ( !AskUsingForm_c(form, &trans) ) return IDPOPT_OK;
  }
  else
  {
    if ( strcmp(keyword, "XlatAsciiOutput") == 0 )
    {
      if ( value_type != IDPOPT_STR ) return IDPOPT_BADTYPE;
      memcpy(trans_dec_pc1, value, 256);
      return IDPOPT_OK;
    }
    if ( strcmp(keyword, "PDP_XLAT_ASCII") != 0 ) return IDPOPT_BADKEY;
    if ( value_type != IDPOPT_BIT ) return IDPOPT_BADTYPE;
    trans = *(ushort*)value;
  }
  ovrtrans.altset(n_asciiX, !trans); // it is strange but it is like this
  ash.XlatAsciiOutput = macro11.XlatAsciiOutput = trans ? trans_dec_pc1 : NULL;
  msg("Character Translation is %s\n", trans ? "enabled" : "disabled");
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
static int notify(processor_t::idp_notify msgid, ...) { // Various messages:
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  int retcode = 1;
  segment_t *sptr;
  static uchar first = 0;

  switch ( msgid ) {
    case processor_t::newseg:
      sptr = va_arg(va, segment_t *);
      sptr->defsr[rVds-ph.regFirstSreg] = find_selector(inf.start_cs); //sptr->sel;
      break;

    case processor_t::init:
      ovrtrans.create(ovrtrans_name);   // it makes no harm to create it again
    default:
      break;

    case processor_t::oldfile:
      m.asect_top = (ushort)ovrtrans.altval(n_asect);
      m.ovrcallbeg = (ushort)ovrtrans.altval(n_ovrbeg);
      m.ovrcallend = (ushort)ovrtrans.altval(n_ovrend);
      if ( ovrtrans.altval(n_asciiX) )
         ash.XlatAsciiOutput = macro11.XlatAsciiOutput = NULL;
      m.ovrtbl_base = (uint32)ovrtrans.altval(n_ovrbas);
    case processor_t::newfile:
      first = 1;
      break;

    case processor_t::loader:
      {
        pdp_ml_t **ml = va_arg(va, pdp_ml_t **);
        netnode  **mn  = va_arg(va, netnode **);
        if ( ml && mn ) {
          *ml = &m;
          *mn = &ovrtrans;
          retcode = 0;
        }
      }
      break;

    case processor_t::move_segm:
                                // A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from - old segment address
                                //       segment_t - moved segment
      {
        ea_t from    = va_arg(va, ea_t);
        segment_t *s = va_arg(va, segment_t *);
        ovrtrans.altshift(from, s->startEA, s->size()); // i'm not sure about this
      }
      break;
  }
  va_end(va);

  return(retcode);
}


//-----------------------------------------------------------------------
static ea_t idaapi load_offset(ea_t base, adiff_t value)
{
  if ( base == m.ovrtbl_base && value >= m.ovrcallbeg && value <= m.ovrcallend )
  {
    ea_t trans = ovrtrans.altval(value);
    if ( trans != 0) return(trans );
  }
  return(base + value);
}

//------------------------------------------------------------------
//  floating point conversion
#include "float.c"
//-----------------------------------------------------------------------

static asm_t *asms[] = { &macro11, NULL };

static const char *shnames[] = { "PDP11", NULL };
static const char *lnames[] = { "DEC PDP-11", NULL };

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0200, 0000 };
static uchar retcode_1[] = { 0201, 0000 };
static uchar retcode_2[] = { 0202, 0000 };
static uchar retcode_3[] = { 0203, 0000 };
static uchar retcode_4[] = { 0204, 0000 };
static uchar retcode_5[] = { 0205, 0000 };
static uchar retcode_6[] = { 0206, 0000 };
static uchar retcode_7[] = { 0207, 0000 };
static uchar retcode_8[] = { 0002, 0000 };
static uchar retcode_9[] = { 0006, 0000 };

static bytes_t retcodes[] = {
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { sizeof(retcode_4), retcode_4 },
 { sizeof(retcode_5), retcode_5 },
 { sizeof(retcode_6), retcode_6 },
 { sizeof(retcode_7), retcode_7 },
 { sizeof(retcode_8), retcode_8 },
 { sizeof(retcode_9), retcode_9 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,
  PLFM_PDP,                     // id
  PR_WORD_INS | PRN_OCT | PR_SEGTRANS, // can use register names for byte names
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  std_gen_segm_footer,

  NULL,

  ana,
  emu,

  out,
  outop,
  pdp_data,
  NULL,         //  cmp_opnd,  // 0 if not cmp 1 if eq
  NULL,         //  can_have_type,  //&op    // 1 -yes 0-no    //reg

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Register names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,                         // Register descriptions
  NULL,                         // Pointer to CPU registers

  rVcs,rVds,
  0,                            // size of a segment register
  rVcs,rVds,

  NULL,                         // No known code start sequences
  retcodes,

  0,pdp_last,
  Instructions,
  NULL,
//
//  Offset Generation Function. Usually NULL.
//
  load_offset,
  0,      // size of tbyte
  realcvt,
  {4,7,19,0},

//
//  Find 'switch' idiom
//      fills 'si' structure with information and returns 1
//      returns 0 if switch is not found.
//      input: 'cmd' structure is correct.
//      this function may use and modify 'cmd' structure
//
  NULL, // int (*is_switch)(switch_info_t *si);

//
//  Generate map file. If this pointer is NULL, the kernel itself
//  will create the map file.
//  This function returns number of lines in output file.
//  0 - empty file, -1 - write error
//
  NULL, // long (*gen_map_file)(FILE *fp);

//
//  Extract address from a string. Returns BADADDR if can't extract.
//  Returns BADADDR-1 if kernel should use standard algorithm.
//
  NULL, // ea_t (*extract_address)(ea_t ea,const char *string,int x);

//
//  Check whether the operand is relative to stack pointer
//  This function is used to determine how to output a stack variable
//  (if it returns 0, then the operand is relative to frame pointer)
//  This function may be absent. If it is absent, then all operands
//  are sp based by default.
//  Define this function only if some stack references use frame pointer
//  instead of stack pointer.
//  returns: 1 - yes, 0 - no
//
   NULL, // int (*is_sp_based)(op_t &x);

//
//  Create a function frame for a newly created function.
//  Set up frame size, its attributes etc.
//  This function may be absent.
//
   NULL, // int (*create_func_frame)(func_t *pfn);


// Get size of function return address in bytes
//      pfn - pointer to function structure, can't be NULL
// If this functin is absent, the kernel will assume
//      4 bytes for 32-bit function
//      2 bytes otherwise

   NULL, // int (*get_frame_retsize)(func_t *pfn);


//
//  Generate stack variable definition line
//  If this function is NULL, then the kernel will create this line itself.
//  Default line is
//              varname = type ptr value
//  where 'type' is one of byte,word,dword,qword,tbyte
//
   NULL, // void (*gen_stkvar_def)(char *buf,const member_t *mptr,long v);

// Generate text representation of an item in a special segment
// i.e. absolute symbols, externs, communal definitions etc.
// returns: 1-overflow, 0-ok

   NULL, // int (*u_outspec)(ea_t ea,uchar segtype);

// Icode of return instruction. It is ok to give any of possible return
// instructions

   pdp_return,

// Set IDP-specific option
//      keyword - keyword encoutered in IDA.CFG file
//                if NULL, then a dialog form should be displayed
//      value_type - type of value of the keyword
//#define IDPOPT_STR 1    // string constant (char *)
//#define IDPOPT_NUM 2    // number (ulong *)
//#define IDPOPT_BIT 3    // bit, yes/no (int *)
//#define IDPOPT_FLT 4    // float (double *)
//      value   - pointer to value
// returns:
//#define IDPOPT_OK       NULL            // ok
//#define IDPOPT_BADKEY   ((char*)1)      // illegal keyword
//#define IDPOPT_BADTYPE  ((char*)2)      // illegal type of value
//#define IDPOPT_BADVALUE ((char*)3)      // illegal value (bad range, for example)
//      otherwise return pointer to an error message

  set_idp_options,
};
