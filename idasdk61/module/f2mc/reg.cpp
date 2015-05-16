/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "f2mc.hpp"
#include <fpro.h>
#include <diskio.hpp>
#include <srarea.hpp>
#include <entry.hpp>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "A",   // accumulator
  "AL",  // accumulator
  "AH",  // accumulator
  "PC",  // program counter
  "SP",  // stack pointer
  "R0",
  "R1",
  "R2",
  "R3",
  "R4",
  "R5",
  "R6",
  "R7",
  "RW0",
  "RW1",
  "RW2",
  "RW3",
  "RW4",
  "RW5",
  "RW6",
  "RW7",
  "RL0",
  "RL1",
  "RL2",
  "RL3",

  "PCB",     // program bank register
  "DTB",     // data bank register
  "ADB",     // additional data bank register
  "SSB",     // system stack bank register
  "USB",     // user stack bank register
  "CCR",     // condition code register
  "DPR",     // direct page register
  "cs","ds", // virtual registers for code and data segments

  "SPB", // stack pointer bank register
  "PS",  // processor status
  "ILM", // interrupt level mask register
  "RP"   // register bank pointer
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x66 };  // retp
static uchar retcode_1[] = { 0x67 };  // ret
static uchar retcode_2[] = { 0x6B };  // reti

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Fujitsu FASM
//-----------------------------------------------------------------------
static asm_t fasm =
{
  AS_N2CHR|AS_NCMAS|ASH_HEXF3|ASD_DECF0|ASO_OCTF1|ASB_BINF3|AS_ONEDUP,
  0,
  "Fujitsu FASM",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  ".org",       // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".data.b",    // byte directive
  ".data.w",    // word directive
  ".data.l",    // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".res.b %s",  // uninited arrays
  ".equ",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // "public" name keyword
  NULL,         // "weak"   name keyword
  NULL,         // "extrn"  name keyword
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
};

static asm_t *asms[] = { &fasm, NULL };

//--------------------------------------------------------------------------
static ioport_t *ports = NULL;
static size_t numports = 0;
char device[MAXSTR] = "";
static const char *cfgname = NULL;

#define CUSTOM1 "FSR"
#include "../iocommon.cpp"

static void load_symbols(int _respect_info)
{
  if ( cfgname != NULL )
  {
    deviceparams[0] = '\0';
    respect_info = _respect_info;
    if ( !inf.like_binary() ) respect_info &= ~2;
    free_ioports(ports, numports);
    ports = read_ioports(&numports, cfgname, device, sizeof(device), callback);
    if ( respect_info )
    {
      for ( int i=0; i < numports; i++ )
      {
        ea_t ea = ports[i].address;
        doByte(ea, 1);
        const char *name = ports[i].name;
        if ( !set_name(ea, name, SN_NOWARN) )
          set_cmt(ea, name, 0);
        else
          set_cmt(ea, ports[i].cmt, true);
      }
    }
  }
}

const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}

const ioport_bit_t *find_bits(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? (*port->bits) : NULL;
}

const char *find_bit(ea_t address, int bit)
{
  const ioport_bit_t *b = find_ioport_bit(ports, numports, address, bit);
  return b ? b->name : NULL;
}

//--------------------------------------------------------------------------
static void f2mc_set_device_name(const char *dev, int _respect_info)
{
  if ( dev != NULL )
  {
    if ( dev != device )
      qstrncpy(device, dev, sizeof(device));
    helper.supset(0, dev);
  }
  load_symbols(_respect_info);
}

//--------------------------------------------------------------------------
static void choose_device(TView *[],int)
{
  if ( choose_ioport_device(cfgname, device, sizeof(device), parse_area_line0) )
    f2mc_set_device_name(device, IORESP_PORT|IORESP_INT);
}

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    static char form[] =
"HELP\n"
"F2MC specific options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
" Use macro instructions\n"
"\n"
"       If this option is on, IDA will try to combine several instructions\n"
"       into a macro instruction\n"
"       For example,\n"
"\n"
"            sbbs    data:7, $1\n"
"            bra     $2\n"
"          $1:\n"
"            jmp     LABEL\n"
"          $2:\n"
"\n"
"       will be replaced by\n"
"\n"
"            sbbs16  data:7, LABEL\n"
"\n"
"ENDHELP\n"
"F2MC specific options\n"
"\n"
" <Use ~m~acro instructions:C>>\n"
"\n"
" <~C~hoose device name:B:0::>\n"
"\n"
"\n";
    AskUsingForm_c(form, &idpflags, choose_device);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT ) return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "F2MC_MACRO") == 0 )
    {
      setflag(idpflags,F2MC_MACRO,*(int*)value);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }
}

//--------------------------------------------------------------------------
netnode helper;
proctype_t ptype = F2MC16LX;
ushort idpflags = F2MC_MACRO;

static proctype_t ptypes[] =
{
  F2MC16L,
  F2MC16LX
};


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
//      __emit__(0xCC);   // debugger trap
      helper.create("$ f2mc");
      {
        char buf[MAXSTR];
        if ( helper.supval(0, buf, sizeof(buf)) > 0 )
          f2mc_set_device_name(buf, IORESP_NONE);
      }
      inf.wide_high_byte_first = 1;
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:   // new file loaded
      set_segm_name(get_first_seg(), "CODE");
      if ( choose_ioport_device(cfgname, device, sizeof(device), parse_area_line0) )
        f2mc_set_device_name(device, IORESP_ALL);
      for ( int i = DTB; i <= rVds; i++ )
      {
        for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->startEA) )
          SetDefaultRegisterValue(s, i, 0);
      }
      break;

    case processor_t::oldfile:   // old file loaded
      idpflags = (ushort)helper.altval(-1);
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.altset(-1, idpflags);
      break;

    case processor_t::newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        switch ( ptype )
        {
          case F2MC16L:
            cfgname = "f2mc16l.cfg";
            break;
          case F2MC16LX:
            cfgname = "f2mc16lx.cfg";
            break;
          default:
            error("interr: setprc");
            break;
        }
        device[0] = '\0';
        if ( get_first_seg() != NULL )
          choose_device(NULL, 0);
      }
      break;

    case processor_t::newasm:    // new assembler type
      break;

    case processor_t::newseg:    // new segment
      break;

  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
static const char *shnames[] =
{ "F2MC16L",
  "F2MC16LX",
  NULL
};
static const char *lnames[] =
{ "Fujitsu F2MC 16L",
  "Fujitsu F2MC 16LX",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_F2MC,                    // id
  PRN_HEX | PR_SEGS | PR_SGROTHER,
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

  DTB,                  // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  F2MC_null,
  F2MC_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  is_sp_based,          // Check whether the operand is relative to stack pointer
  create_func_frame,    // create frame of newly created function
  NULL,                 // Get size of function return address in bytes
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  F2MC_ret,             // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
