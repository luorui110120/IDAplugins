/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "tms320c54.hpp"
#include <fpro.h>
#include <diskio.hpp>
#include <srarea.hpp>
#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "PC",  // program counter
  "A",   // accumulator
  "B",   // accumulator

  // flags
  "ASM", // 5-bit accumulator shift mode field in ST1
  "ARP", // auxiliary register pointer
  "TS",  // shift value (bits 5-0 of T)
  "OVB",
  "OVA",
  "C",
  "TC",
  "CMPT",
  "FRCT",
  "C16",
  "SXM",
  "OVM",
  "INTM",
  "HM",
  "XF",
  "BRAF",

  // CPU memory mapped registers
  "IMR",
  "IFR",
  "ST0",
  "ST1",
  "AL",
  "AH",
  "AG",
  "BL",
  "BH",
  "BG",
  "T",   // temporary register
  "TRN", // transition register
  "AR0",
  "AR1",
  "AR2",
  "AR3",
  "AR4",
  "AR5",
  "AR6",
  "AR7",
  "SP",  // stack pointer
  "BK",
  "BRC",
  "RSA",
  "REA",
  "PMST",

  // segment registers
  "XPC", // program counter extension register
  "CPL", // compiler mode
  "DP",  // data page pointer
  "cs","ds", // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0xF4, 0xE4 }; // fret
static uchar retcode_1[] = { 0xF6, 0xE4 }; // fretd
static uchar retcode_2[] = { 0xF4, 0xE5 }; // frete
static uchar retcode_3[] = { 0xF6, 0xE5 }; // freted
static uchar retcode_4[] = { 0xFC }; // rc
static uchar retcode_5[] = { 0xFE }; // rcd
static uchar retcode_6[] = { 0xFC, 0x00 }; // ret
static uchar retcode_7[] = { 0xFE, 0x00 }; // retd
static uchar retcode_8[] = { 0xF4, 0xEA }; // rete
static uchar retcode_9[] = { 0xF6, 0xEA }; // reted
static uchar retcode_10[] = { 0xF4, 0x9A }; // retf
static uchar retcode_11[] = { 0xF6, 0x9A }; // retfd

static bytes_t retcodes[] =
{
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
 { sizeof(retcode_10), retcode_10 },
 { sizeof(retcode_11), retcode_11 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      TMS320C54 ASM
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
  ".space 16*%s",// uninited arrays
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
  AS2_STRINV    // invert string byte order
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
  AS2_STRINV,   // invert string byte order
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
static const char *cfgname = "tms320c54.cfg";
ea_t dataseg;

static void load_symbols(void)
{
  free_ioports(ports, numports);
  ports = read_ioports(&numports, cfgname, device, sizeof(device), NULL);
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

//----------------------------------------------------------------------
static void apply_symbols(void)
{
  for ( int i=0; i < numports; i++ )
  {
    ea_t ea = calc_data_mem(ports[i].address);
    segment_t *s = getseg(ea);
    if ( s == NULL || s->type != SEG_IMEM ) continue;
    doByte(ea, 1);
    const char *name = ports[i].name;
    if ( !set_name(ea, name, SN_NOWARN) )
      set_cmt(ea, name, 0);
  }
}

//--------------------------------------------------------------------------
inline void set_device_name(const char *dev)
{
  if ( dev != NULL )
    qstrncpy(device, dev, sizeof(device));
}

//--------------------------------------------------------------------------
inline void swap(unsigned char &c1, unsigned char &c2)
{
  unsigned char tmp = c1;
  c1 = c2;
  c2 = tmp;
}

int idaapi tms_realcvt(void *m, ushort *e, ushort swt)
{
  int ret;
  switch ( swt )
  {
    case 1:                // float to e
      {
        unsigned char p[4];
        memcpy(p, m, 4);
        swap(p[0], p[1]);
        swap(p[2], p[3]);
        ret = ieee_realcvt(p, e, swt);
        break;
      }
    case 011:              // float output
      {
        ret = ieee_realcvt(m, e, swt);
        unsigned char *p = (unsigned char*)m;
        swap(p[0], p[1]);
        swap(p[2], p[3]);
        break;
      }
    default:
      ret = ieee_realcvt(m, e, swt);
  }
  return ret;
}

//--------------------------------------------------------------------------

#include "../mapping.cpp"

netnode helper;
proctype_t ptype = TMS320C54;
ushort idpflags = TMS320C54_IO|TMS320C54_MMR;


static proctype_t ptypes[] =
{
  TMS320C54
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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4063)
#endif
  switch ( msgid )
  {
    case processor_t::init:
      helper.create("$ tms320c54");
      {
        char buf[MAXSTR];
        if ( helper.supval(0, buf, sizeof(buf)) > 0 )
          set_device_name(buf);
      }
      inf.mf = 1; // MSB first
      inf.wide_high_byte_first = 1;
      dataseg = helper.altval(0);
      init_mapping(0x1000, "tms320c54");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:   // new file loaded
      inf.wide_high_byte_first = 0;
      {
        segment_t *s = get_first_seg();
        if ( s != NULL )
          apply_symbols();
        while (s)
        {
          char sclas[MAXNAMELEN];
          get_segm_class(s, sclas, sizeof(sclas));
          for ( int i = XPC; i <= rVds; i++ )
            SetDefaultRegisterValue(s, i, BADSEL);
          if ( !strcmp(sclas, "CODE") )
            SetDefaultRegisterValue(s, XPC, s->startEA >> 16);
          s = get_next_seg(s->startEA);
        }
      }
      break;

    case processor_t::loader+2:
      dataseg = va_arg(va, ea_t);
      break;

    case processor_t::oldfile:   // old file loaded
      inf.wide_high_byte_first = 0;
      idpflags = (ushort)helper.altval(-1);
      break;

    case processor_t::newbinary:
      inf.wide_high_byte_first = 1;
      break;
    case processor_t::endbinary:
      inf.wide_high_byte_first = 0;
      break;

    case processor_t::closebase:
      helper.altset(0,  dataseg);
      helper.altset(-1, idpflags);
      helper.supset(0,  device);
      term_mapping();
      break;

    case processor_t::savebase:
      helper.altset(0,  dataseg);
      helper.altset(-1, idpflags);
      helper.supset(0,  device);
      save_mapping();
      break;

    case processor_t::newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        switch ( ptype )
        {
          case TMS320C54:
            break;
          default:
            error("interr: setprc");
            break;
        }
        device[0] = '\0';
        load_symbols();
      }
      break;

    case processor_t::newasm:    // new assembler type
      break;

    case processor_t::newseg:    // new segment
      break;

    case processor_t::is_basic_block_end:
      return is_basic_block_end() ? 2 : 0;

    case processor_t::is_sane_insn:
      {
        int no_crefs = va_arg(va, int);
        // add 0, a is not a sane instruction without crefs to it
        if ( no_crefs && get_full_byte(cmd.ea) == 0 )
          return 0;
      }
      break;

  }
#ifdef _MSC_VER
#pragma warning(pop)
#endif
  va_end(va);
  return 1;
}

//--------------------------------------------------------------------------
static void choose_device(TView *[],int)
{
  if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
  {
    load_symbols();
    apply_symbols();
  }
}

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    static const char form[] =
"HELP\n"
"TMS320C54 specific options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
" Use I/O definitions\n"
"\n"
"       If this option is on, IDA will use I/O definitions\n"
"       from the configuration file into a macro instruction.\n"
"\n"
" Detect memory mapped registers\n"
"\n"
"       If this option is on, IDA will replace addresses\n"
"       by an equivalent memory mapped register.\n"
"\n"
" Device name\n"
"\n"
"       Choose the exact device name for the processor.\n"
"       If you don't see the name you want, you can add\n"
"       a section about it to the tms320c54.cfg file\n"
"\n"
" Data segment address\n"
"\n"
"       The data segment linear address.\n"
"\n"
"ENDHELP\n"
"TMS320C54 specific options\n"
"\n"
" <Use ~I~/O definitions:C>\n"
" <Detect memory mapped ~r~egisters:C>>\n"
"\n"
" <~C~hoose device name:B:0:::>\n"
"\n"
" <~D~ata segment address:N:200:12::>\n"
"\n"
" <~A~dd mapping:B:0:::>      <R~e~move mapping:B:0:::>\n"
"\n"
" Current mappings :\n"
"\n";
    int form_len = qstrlen(form);
    int bufsize = form_len + 32 * 64; /* max 64 char by mapping, max 32 mappings */
    char *buf = (char*) qalloc(bufsize);
    qstrncpy(buf, form, bufsize);
    print_mappings(buf + form_len, bufsize - form_len);
    AskUsingForm_c(buf, &idpflags, choose_device, &dataseg, add_mapping, remove_mapping);
    qfree(buf);
    return IDPOPT_OK;
  }
  else
  {
    if ( strcmp(keyword, "TMS320C54_DSEG") == 0 )
    {
      if ( value_type != IDPOPT_NUM ) return IDPOPT_BADTYPE;
      dataseg = *(uval_t *)value;
      return IDPOPT_OK;
    }
    if ( value_type != IDPOPT_BIT ) return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "TMS320C54_IO") == 0 )
    {
      setflag(idpflags,TMS320C54_IO,*(int*)value);
      return IDPOPT_OK;
    }
    else if ( strcmp(keyword, "TMS320C54_MMR") == 0 )
    {
      setflag(idpflags,TMS320C54_MMR,*(int*)value);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }
}

//-----------------------------------------------------------------------
static const char *shnames[] =
{
  "TMS32054",
  NULL
};
static const char *lnames[] =
{
  "Texas Instruments TMS320C54",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_TMS320C54,
  PRN_HEX | PR_SEGS | PR_SGROTHER | PR_ALIGN,
  16,                           // 16 bits in a byte for code segments
  16,                           // 16 bits in a byte for other segments

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

  XPC,                  // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  TMS320C54_null,
  TMS320C54_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  tms_realcvt,          // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0,7,15,19 },        // char real_width[4];
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
  tms_get_frame_retsize,// Get size of function return address in bytes
  gen_stkvar_def,       // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  TMS320C54_ret,        // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
