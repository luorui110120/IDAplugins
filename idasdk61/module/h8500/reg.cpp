/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <fpro.h>
#include <diskio.hpp>

#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "fp",  "sp",
  "sr",   "ccr",  "?",   "br",  "ep",  "dp",  "cp",  "tp",
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x56, 0x70 };  // rte
static uchar retcode_1[] = { 0x54, 0x70 };  // rts

static const bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//------------------------------------------------------------------
static void idaapi func_header(func_t *pfn)
{
  std_gen_func_header(pfn);
  char namebuf[MAXSTR];
  ea_t ea = pfn->startEA;
  char *const nend = namebuf + sizeof(namebuf);
  char *ptr = tag_addr(namebuf, nend, ea);
  get_demangled_name(BADADDR, ea,
     ptr, nend-ptr,
     inf.long_demnames, DEMNAM_NAME, 0);
  gen_name_decl(ea, namebuf);
  gl_xref = 1;
  printf_line(0, "%s" COLSTR(":", SCOLOR_SYMBOL) " "
                 SCOLOR_ON SCOLOR_AUTOCMT
                 "%s %s"
                 SCOLOR_OFF SCOLOR_AUTOCMT,
                 namebuf,
                 ash.cmnt,
                 (pfn->flags & FUNC_FAR) != 0 ? "far" : "near");
}

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static asm_t gas =
{
  AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  ".org",       // org
  NULL,         // end

  "!",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  NULL,         // current IP (instruction pointer)
  func_header,  // func_header
  NULL,         // func_footer
  ".globl",     // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
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
  AS2_COLONSUF, // flag2
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static asm_t *asms[] = { &gas, NULL };

//--------------------------------------------------------------------------
struct sym_t
{
  int address;
  char *name;
};

static sym_t *syms = NULL;
static int numsyms = 0;

//--------------------------------------------------------------------------
static void free_syms(void)
{
  for ( int i=0; i < numsyms; i++ )
    qfree(syms[i].name);
  qfree(syms);
  numsyms = 0;
  syms = NULL;
}

//--------------------------------------------------------------------------
static void load_symbols(const char *file)
{
  free_syms();
  if ( file == NULL )
    return;
  char cfgpath[QMAXPATH];
  const char *rfile = getsysfile(cfgpath, sizeof(cfgpath), file, CFG_SUBDIR);
  if ( rfile == NULL )
  {
NOFILE:
//    warning("Can't open %s, symbol definitions are not loaded", file);
    return;
  }
  FILE *fp = fopenRT(rfile);
  if ( fp == NULL )
    goto NOFILE;
  int ln = 0;
  char line[MAXSTR];
  while ( qfgets(line, sizeof(line), fp) )
  {
    ln++;
    line[strlen(line)-1] = '\0';
    trim(line);
    if ( line[0] == ';' || line[0] == ' ' || line[0] == '\0' ) continue;
    char word[MAXSTR];
    int addr;
    if ( sscanf(line, "%s %i", word, &addr) != 2 )
    {
      warning("%s: syntax error at line %d", file, ln);
      break;
    }
    int i;
    for ( i=0; i < numsyms; i++)
    {
      if ( syms[i].address == addr && strcmp(syms[i].name, word) != 0 )
      {
        warning("%s: duplicate address %#x at line %d", file, addr, ln);
        break;
      }
    }
    if ( i != numsyms ) break;
    syms = qrealloc_array<sym_t>(syms, numsyms + 1);
    if ( syms == NULL ) nomem("h8/500 symbols");
    syms[numsyms].address = addr;
    syms[numsyms].name = qstrdup(word);
    numsyms++;
  }
  qfclose(fp);
}

//--------------------------------------------------------------------------
const char *find_sym(int address)
{
  for ( int i=0; i < numsyms; i++ )
    if ( syms[i].address == address ) return syms[i].name;
  return NULL;
}

//--------------------------------------------------------------------------
static void create_segment_registers(void)
{
  for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->startEA) )
  {
    segreg_t *sr = getSRarea(s->startEA);
    if ( sr == NULL )
    {
      segreg_t sr;
      memset(&sr, 0, sizeof(sr));
      sr.startEA = s->startEA;
      sr.endEA   = s->endEA;
      sr.settags(SR_autostart);
      SRareas.create_area(&sr);
    }
  }
}

//--------------------------------------------------------------------------
netnode helper;
ushort idpflags = AFIDP_MIXSIZE;

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
      helper.create("$ h8/500");
      inf.mf = 1;
    default:
      break;

    case processor_t::term:
      free_syms();
      break;

    case processor_t::oldfile:   // old file loaded
      idpflags = ushort(helper.altval(-1) + 1);
      create_segment_registers();
      // no break
    case processor_t::newfile:   // new file loaded
      load_symbols("h8500.cfg");
      inf.mf = 1;
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.altset(-1, idpflags - 1);
      break;

    case processor_t::newseg:    // new segment
      {
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[BR-ph.regFirstSreg] = 0;
        sptr->defsr[DP-ph.regFirstSreg] = 0;
      }
      break;

    case processor_t::is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        return is_jump_func(pfn, jump_target);
      }

    case processor_t::is_sane_insn:
      return is_sane_insn(va_arg(va, int));

    case processor_t::may_be_func:
                                // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
      return may_be_func();

  }
  va_end(va);
  return 1;
}

//------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
    static char form[] =
"HELP\n"
"H8/500 specific analyzer options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
"Disassemble mixed size instructions\n"
"\n"
"        According to the documentation, instructions like\n"
"\n"
"        cmp:g.b #1:16, @0x222:16\n"
"\n"
"        are not allowed. The correct instruction is:\n"
"\n"
"        cmp:g.b #1:8, @0x222:16\n"
"\n"
"        The size of the first operand should agree with the size\n"
"        of the instruction. (exception mov:g)\n"
"\n"
"ENDHELP\n"
"H8/500 specific analyzer options\n"
"\n"
// m
" <Disassemble ~m~ixed size instructions:C>>\n"
"\n"
"\n";

  if ( keyword == NULL )
  {
    AskUsingForm_c(form, &idpflags);
    return IDPOPT_OK;
  }
  if ( strcmp(keyword,"H8500_MIXED_SIZE") == 0 )
  {
    if ( value_type != IDPOPT_BIT ) return IDPOPT_BADTYPE;
    setflag(idpflags, AFIDP_MIXSIZE, *(int*)value);
    return IDPOPT_OK;
  }
  return IDPOPT_BADKEY;
}

//-----------------------------------------------------------------------
static const char *shnames[] = { "h8500", NULL };
static const char *lnames[] = {
  "Hitachi H8/500",
  NULL
};

//-----------------------------------------------------------------------
// temporary solution for v4.7
static ea_t idaapi h8_extract_address(ea_t screen_ea, const char *string, int x)
{
  size_t len = strlen(string);
  if ( len == 0 || x > len ) return BADADDR;
  if ( x == len ) x--;
  const char *ptr = string + x;
  while ( ptr > string && qisxdigit(ptr[-1]) ) ptr--;
  const char *start = ptr;
  while ( qisxdigit(ptr[0]) ) ptr++;
  len = ptr - start;
  char buf[MAXSTR];
  memcpy(buf, start, len);
  buf[len] = '\0';
  ea_t ea = BADADDR;
  str2ea(buf, &ea, screen_ea);
  return ea;
}

//------------------------------------------------------------------------
static bool idaapi can_have_type(op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:
    case o_reg:
    case o_reglist:
      return false;
    case o_phrase:
      return x.phtype == ph_normal;
  }
  return true;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_H8500,                   // id
  PRN_HEX|PR_SEGS|PR_SGROTHER,
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

  assume,               // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  intel_data,           // generate ...                    data directive
  NULL,                 // compare operands
  can_have_type,

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  BR,                   // first
  TP,                   // last
  1,                    // size of a segment register
  CP, DP,

  NULL,                 // No known code start sequences
  retcodes,

  H8500_null,
  H8500_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  ieee_realcvt,         // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  h8_extract_address,   // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  is_sp_based,          // int (*is_sp_based)(op_t &x); -- always, so leave it NULL
  create_func_frame,    // int (*create_func_frame)(func_t *pfn);
  h8500_get_frame_retsize, // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,long v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  H8500_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
