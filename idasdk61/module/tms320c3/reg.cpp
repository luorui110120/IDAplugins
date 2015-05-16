/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <math.h>
#include "tms320c3x.hpp"
#include <fpro.h>
#include <diskio.hpp>
#include <srarea.hpp>
#include <entry.hpp>
#include <ieee.h>

static const char *register_names[] =
{
        // Extended-precision registers
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        // Auxiliary registers
        "ar0",
        "ar1",
        "ar2",
        "ar3",
        "ar4",
        "ar5",
        "ar6",
        "ar7",

        // Index register n
        "ir0",
        "ir1",

        "bk",   // Block-size register
        "sp",   // System-stack pointer
        "st",   // Status register
        "ie",   // CPU/DMA interrupt-enable register
        "if",   // CPU interrupt flag
        "iof",  // I/O flag
        "rs",   // Repeat start-address
        "re",   // Repeat end-address
        "rc",   // Repeat counter

        // segment registers
        "dp",      // Data-page pointer
        "cs","ds", // virtual registers for code and data segments

};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x78, 0x80, 0x00, 0x00 }; // 0x78800000    //retsu
static uchar retcode_1[] = { 0x78, 0x00, 0x00, 0x00 }; // 0x78000000    //retiu

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      TMS320C3X ASM
//-----------------------------------------------------------------------
static asm_t fasm =
{
  AS_N2CHR|ASH_HEXF0|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP|AS_COLON,
  0,
  "ASM500",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  NULL,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space 32*%s",// uninited arrays
  ".asg",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".ref",       // "extrn"  name keyword
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  AS2_BYTE1CHAR,// one character per byte
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static asm_t gnuasm =
{
  AS_N2CHR|ASH_HEXF3|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP|AS_COLON|AS_ASCIIC,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  NULL,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".zero 2*%s", // uninited arrays
  ".asg",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  ".weak",      // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  AS2_BYTE1CHAR,// one character per byte
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static asm_t *asms[] = { &fasm, &gnuasm, NULL };

//--------------------------------------------------------------------------
static ioport_t *ports = NULL;
static size_t numports = 0;
char device[MAXSTR] = "";

static bool entry_processing(ea_t ea, const char *name, const char *cmt)
{
  set_name(ea, name);
  set_cmt(ea, cmt, 0);
  return true;
}

#define ENTRY_PROCESSING entry_processing
#include "../iocommon.cpp"

//----------------------------------------------------------------------
static bool select_device(int respect_info)
{
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
  {
    qstrncpy(device, NONEPROC, sizeof(device));
    return false;
  }

  if ( !display_infotype_dialog(IORESP_ALL, &respect_info, cfgfile) )
    return false;

  set_device_name(device, respect_info);
  return true;
}

//----------------------------------------------------------------------
static float conv32(int32 A){   // Преобразование 32 bit TMS float -> double

        int32  mask, f, i, s;
        float mant;
        int8    e;

        // Порядок (exponent) signed 8 bit
        e = A >> 24;

        //Знак  (sign) boolean 1 bit
        s =  (A & 0x00800000) >> 23 ;

        //дробная часть (fractional) unsigned 23 bit
        f =  A & 0x007FFFFF;

        if ( s )
        {
                f ^= 0x007FFFFF;
                f++;
        }

        mant = 1;       //Мантисса (1<M<2)
        mask =       0x00800000;        // Маска текущего бита (начинаем со знакового разряда потому, что может возниктунь дополнение при Neg мантиссе)

        for (i = 0; i <= 23; i++)
        {       //Получение мантиссы
    if ( f & mask) mant += (float)pow(double(2), -i );
                mask >>= 1;
        }

        if ( (e == -128) && (f == 0) && (s==0) ) mant = 0;

  return  float(pow(double(-1), s) * mant * pow(double(2), e));
}

//----------------------------------------------------------------------
static float conv16(int16 A){   // Преобразование 16 bit TMS float -> double

        int16  mask, f, i, s;
        float mant;
        int8    e;


        // Порядок (exponent) signed 4 bit
        e = A >> 12;
        if ( e>7) e = -((e ^ 0x0f) + 1 );

        //Знак  (sign) boolean 1 bit
        s =  (A & 0x0800) >> 11 ;

        //дробная часть (fractional) unsigned 11 bit
        f =  A & 0x07FF;

        if ( s )
        {
            f ^= 0x07FF;
            f++;
        }

        mant = 1;       //Мантисса (1<M<2)
        mask =       0x0800;    // Маска текущего бита (начинаем со знакового разряда потому, что может возниктунь дополнение при Neg мантиссе)

        for (i = 0; i <= 11; i++)
        {       //Получение мантиссы
      if ( f & mask) mant += (float)pow(double(2), -i );
            mask >>= 1;
        }

        if ( (e == -8) && (f == 0) && (s==0) ) mant = 0;

  return float(pow(double(-1), s) * mant * pow(double(2), e));
}

//--------------------------------------------------------------------------
int idaapi tms_realcvt(void *m, ushort *e, ushort swt)
{
  int ret;
  int32 A;
  int16 B;

  union {
        float pfl;
        int32 pint;
  };

  switch ( swt )
  {

   case 0:                // TmsFloat 16bit to e
      {
        memcpy(&B, m, 2);
        pfl = conv16(B);
        pint = swap32(pint);
        ret = ieee_realcvt(&pint, e, 1);
        break;
      }
   case 1:                // TmsFloat 32bit to e
      {
        memcpy(&A, m, 4);
        pfl = conv32(A);
        pint = swap32(pint);
        ret = ieee_realcvt(&pint, e, 1);
        break;
      }
    default:
        msg("real_cvt_error swt = %d \n", swt);
      return -1;
  }
  return ret;
}

//--------------------------------------------------------------------------
netnode helper;
ushort idpflags;        // not used?

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
    case processor_t::init:
      helper.create("$ tms320c3x");
      inf.mf = 1; // MSB first
      inf.wide_high_byte_first = 1;
      init_analyzer();
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:   // new file loaded
      inf.wide_high_byte_first = 0;
      {
        segment_t *s0 = get_first_seg();
        if ( s0 != NULL )
        {
          set_segm_name(s0, "CODE");
          segment_t *s1 = get_next_seg(s0->startEA);
          for (int i = dp; i <= rVds; i++)
          {
            SetDefaultRegisterValue(s0, i, BADSEL);
            SetDefaultRegisterValue(s1, i, BADSEL);
          }
        }
      }
      select_device(IORESP_ALL);
      break;

    case processor_t::oldfile:   // old file loaded
      inf.wide_high_byte_first = 0;
      idpflags = (ushort)helper.altval(-1);
      {
        char buf[MAXSTR];
        if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
          set_device_name(buf, IORESP_NONE);
      }
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.altset(-1, idpflags);
      break;

    case processor_t::is_basic_block_end:
      return is_basic_block_end() ? 2 : 0;
  }
  va_end(va);
  return 1;
}

//--------------------------------------------------------------------------
static const char *idaapi set_idp_options(const char *keyword, int, const void *)
{
  if ( keyword != NULL )
    return IDPOPT_BADKEY;
  select_device(IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//-----------------------------------------------------------------------
static const char *shnames[] =
{
  "TMS320C3",
  NULL
};
static const char *lnames[] =
{
  "Texas Instruments TMS320C3X",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_TMS320C3,
  PRN_HEX | PR_SEGS | PR_SGROTHER | PR_ALIGN,
  32,                           // 32 bits in a byte for code segments
  32,                           // 32 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  assumes,              // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  intel_data,           // generate ...                    data
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  dp,                   // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  TMS320C3X_null,
  TMS320C3X_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  tms_realcvt,          // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 4,7,15,19 },        // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // Check whether the operand is relative to stack pointer
  create_func_frame,    // create frame of newly created function
  NULL,                 // Get size of function return address in bytes
  gen_stkvar_def,       // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  TMS320C3X_RETSU,      // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
