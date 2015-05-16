/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"
#include <diskio.hpp>
#include <typeinf.hpp>

#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  // general registers (r0 is always 0)
  // r31 is for BLE instruction
  "%r0",  "%r1",  "%rp",  "%r3",  "%r4",  "%r5",  "%r6",  "%r7",
  "%r8",  "%r9",  "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
  "%r16", "%r17", "%r18", "%r19", "%r20", "%r21", "%r22", "%r23",
  "%r24", "%r25", "%r26", "%dp",  "%r28", "%r29", "%sp",  "%r31",
  // space registers
  "%sr0", "%sr1", "%sr2", "%sr3", "%sr4", "%sr5", "%sr6", "%sr7",
  // control registers
  "%rctr", "%cr1",  "%cr2",  "%cr3",  "%cr4",  "%cr5",  "%cr6",  "%cr7",
  "%pidr1","%pidr2","%ccr",  "%sar",  "%pidr3","%pidr4","%iva",  "%eiem",
  "%itmr", "%pcsq", "pcoq",  "%iir",  "%isr",  "%ior",  "%ipsw", "%eirr",
  "%tr0",  "%tr1",  "%tr2",  "%tr3",  "%tr4",  "%tr5",  "%tr6",  "%tr7",
  // floating-point registers
  "%fpsr", "%fr1",  "%fr2",  "%fr3",  "%fr4",  "%fr5",  "%fr6",  "%fr7",
  "%fr8",  "%fr9",  "%fr10", "%fr11", "%fr12", "%fr13", "%fr14", "%fr15",
  "%fr16", "%fr17", "%fr18", "%fr19", "%fr20", "%fr21", "%fr22", "%fr23",
  "%fr24", "%fr25", "%fr26", "%fr27", "%fr28", "%fr29", "%fr30", "%fr31",
  // register halves
  "%fr16l", "%fr17l", "%fr18l", "%fr19l", "%fr20l", "%fr21l", "%fr22l", "%fr23l",
  "%fr24l", "%fr25l", "%fr26l", "%fr27l", "%fr28l", "%fr29l", "%fr30l", "%fr31l",
  "%fr16r", "%fr17r", "%fr18r", "%fr19r", "%fr20r", "%fr21r", "%fr22r", "%fr23r",
  "%fr24r", "%fr25r", "%fr26r", "%fr27r", "%fr28r", "%fr29r", "%fr30r", "%fr31r",
  // condition bits
  "%ca0", "%ca1", "%ca2", "%ca3", "%ca4", "%ca5", "%ca6",

  "dp",            // segment register to represent DP
  "cs","ds",       // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0xE8, 0x40, 0xC0, 0x00 };  // bv %r0(%rp)

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static asm_t gas =
{
  AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU-like hypothetical assembler",
  0,
  NULL,         // header lines
  NULL,         // bad instructions
  ".org",       // org
  NULL,         // end

  "#",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  ".quad",      // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  ".ds.#s(b,w,l,d) #d, #v", // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  ".",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "mod",        // mod
  "and",        // and
  "or",         // or
  "xor",        // xor
  "not",        // not
  "shl",        // shl
  "shr",        // shr
  NULL,         // sizeof
  0,            // flag2
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static asm_t *asms[] = { &gas, NULL };

//--------------------------------------------------------------------------
netnode helper;

//--------------------------------------------------------------------------
static void setup_got(void)
{
  netnode n("$ got");
  if ( exist(n) ) got = n.altval(0) - 1;
  if ( got == BADADDR ) get_name_value(BADADDR, "_GLOBAL_OFFSET_TABLE_", &got);
  if ( got == BADADDR )
  {
    segment_t *s = get_segm_by_name(".got");
    if ( s != NULL ) got = s->startEA;
  }
  msg("DP is assumed to be %08a\n", got);
}

//--------------------------------------------------------------------------
static void handle_new_flags(void)
{
  if ( mnemonic() )
  {
    register_names[26] = "%arg0";
    register_names[25] = "%arg1";
    register_names[24] = "%arg2";
    register_names[23] = "%arg3";
    register_names[28] = "%ret0";
  }
  else
  {
    register_names[26] = "%r26";
    register_names[25] = "%r25";
    register_names[24] = "%r24";
    register_names[23] = "%r23";
    register_names[28] = "%r28";
  }
}

//--------------------------------------------------------------------------
static ioport_t *syscalls;
static size_t nsyscalls;

const char *get_syscall_name(int syscall)
{
  const ioport_t *p = find_ioport(syscalls, nsyscalls, syscall);
  return p == NULL ? NULL : p->name;
}

//--------------------------------------------------------------------------

int ptype;
ea_t got = BADADDR;

ushort idpflags = IDP_SIMPLIFY;

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
      helper.create("$ hppa");
      inf.mf = 1;         // always big endian
      syscalls = read_ioports(&nsyscalls, "hpux.cfg", NULL, 0, NULL);
    default:
      break;

    case processor_t::term:
      free_ioports(syscalls, nsyscalls);
      break;

    case processor_t::newfile:      // new file loaded
      handle_new_flags();
      setup_got();
      break;

    case processor_t::oldfile:      // old file loaded
      idpflags = ushort(helper.altval(-1));
      handle_new_flags();
      setup_got();
      break;

    case processor_t::newprc:    // new processor type
      break;

    case processor_t::newasm:    // new assembler type
      break;

    case processor_t::newseg:    // new segment
      {
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[ rVds-ph.regFirstSreg] = find_selector(sptr->sel);
        sptr->defsr[DPSEG-ph.regFirstSreg] = 0;
      }
      break;

    case processor_t::is_sane_insn:
      return is_sane_insn(va_arg(va, int));

    case processor_t::may_be_func:
                                // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
      return may_be_func();

    case processor_t::is_basic_block_end:
      return is_basic_block_end() ? 2 : 0;

// +++ TYPE CALLBACKS (only 32-bit programs for the moment)
    case processor_t::decorate_name:
      {
        const til_t *ti    = va_arg(va, const til_t *);
        const char *name   = va_arg(va, const char *);
        const type_t *type = va_arg(va, const type_t *);
        char *outbuf       = va_arg(va, char *);
        size_t bufsize     = va_arg(va, size_t);
        bool mangle        = va_argi(va, bool);
        cm_t real_cc       = va_argi(va, cm_t);
        return gen_decorate_name(ti, name, type, outbuf, bufsize, mangle, real_cc);
      }

    case processor_t::max_ptr_size:
      return 4+1;

    case processor_t::based_ptr:
      {
        /*unsigned int ptrt =*/ va_arg(va, unsigned int);
        char **ptrname    = va_arg(va, char **);
        *ptrname = NULL;
        return 0;                       // returns: size of type
      }

    case processor_t::get_default_enum_size: // get default enum size
                                // args:  cm_t cm
                                // returns: sizeof(enum)
      {
//        cm_t cm        =  va_argi(va, cm_t);
        return inf.cc.size_e;
      }

    case processor_t::calc_arglocs2:
      {
        const type_t *type = va_arg(va, const type_t *);
        cm_t cc            = va_argi(va, cm_t);
        uint32 *arglocs    = va_arg(va, uint32 *);
        return hppa_calc_arglocs(type, cc, arglocs);
      }

    // this callback is never used because the stack pointer does not
    // change for each argument
    // we use ph.use_arg_types instead
    case processor_t::use_stkarg_type:
                                    // use information about a stack argument
      {
        return false;               // say failed all the time
                                    // so that the kernel attaches a comment
      }

    case processor_t::use_regarg_type2:
      {
        int *retidx                 = va_arg(va, int *);
        ea_t ea                     = va_arg(va, ea_t);
        const type_t * const *types = va_arg(va, const type_t * const *);
        const char * const *names   = va_arg(va, const char * const *);
        const uint32 *regs          = va_arg(va, const uint32 *);
        int n                       = va_arg(va, int);
        *retidx = hppa_use_regvar_type(ea, types, names, regs, n);
        return 2;
      }

    case processor_t::use_arg_types2:
      {
        ea_t ea                     = va_arg(va, ea_t);
        const type_t * const *types = va_arg(va, const type_t * const *);
        const char * const *names   = va_arg(va, const char * const *);
        const uint32 *arglocs       = va_arg(va, const uint32 *);
        int n                       = va_arg(va, int);
        const type_t **rtypes       = va_arg(va, const type_t **);
        const char **rnames         = va_arg(va, const char **);
        uint32 *regs                = va_arg(va, uint32 *);
        int *rn                     = va_arg(va, int *);
        *rn = hppa_use_arg_types(ea, types, names, arglocs, n,
                                 rtypes, rnames, regs, *rn);
        return 2;
      }

    case processor_t::get_fastcall_regs2:
      {
        const int **regs = va_arg(va, const int **);
        static const int fregs[] = { R26, R25, R24, R23, -1 };
        *regs = fregs;
        return (qnumber(fregs) - 1) + 2;
      }

    case processor_t::get_thiscall_regs2:
      {
        const int **regs = va_arg(va, const int **);
        *regs = NULL;
        return 2;
      }

    case processor_t::calc_cdecl_purged_bytes2:
                                // calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 2;
      }

    case processor_t::get_stkarg_offset2:
                                // get offset from SP to the first stack argument
                                // args: none
                                // returns: the offset+2
      return -0x34 + 2;

// --- TYPE CALLBACKS
    case processor_t::loader:
      break;

    // BEGIN SUPPORT FOR OLD PLUGINS
    case processor_t::obsolete_use_regarg_type:
      {
        ea_t ea                     = va_arg(va, ea_t);
        const type_t * const *types = va_arg(va, const type_t * const *);
        const char * const *names   = va_arg(va, const char * const *);
        const uint32 *regs          = va_arg(va, const uint32 *);
        int n                       = va_arg(va, int);
        return hppa_use_regvar_type(ea, types, names, regs, n);
      }

    case processor_t::obsolete_use_arg_types:
      {
        ea_t ea                     = va_arg(va, ea_t);
        const type_t * const *types = va_arg(va, const type_t * const *);
        const char * const *names   = va_arg(va, const char * const *);
        const uint32 *arglocs       = va_arg(va, const uint32 *);
        int n                       = va_arg(va, int);
        const type_t **rtypes       = va_arg(va, const type_t **);
        const char **rnames         = va_arg(va, const char **);
        uint32 *regs                = va_arg(va, uint32 *);
        int rn                      = va_arg(va, int);
        return hppa_use_arg_types(ea, types, names, arglocs, n,
                                  rtypes, rnames, regs, rn);
      }

    case processor_t::obsolete_get_fastcall_regs:
      {
        const int **regs = va_arg(va, const int **);
        static const int fregs[] = { R26, R25, R24, R23, -1 };
        *regs = fregs;
        return qnumber(fregs) - 1;
      }

    case processor_t::obsolete_get_thiscall_regs:
      {
        const int **regs = va_arg(va, const int **);
        *regs = NULL;
        return 0;
      }

    case processor_t::obsolete_calc_cdecl_purged_bytes:
      return 0;

    case processor_t::obsolete_get_stkarg_offset:
      return -0x34;
    // END SUPPORT FOR OLD PLUGINS
  }
  va_end(va);
  return 1;
}

//--------------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
    static char form[] =
"HELP\n"
"HP PA-RISC specific options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
" Simplify instructions\n"
"\n"
"       If this option is on, IDA will simplify instructions and replace\n"
"       them by clearer pseudo-instructions\n"
"       For example,\n"
"\n"
"               or      0, 0, 0\n"
"\n"
"       will be replaced by\n"
"\n"
"               nop\n"
"\n"
" PSW bit W is on\n"
"\n"
"       If this option is on, IDA will disassemble instructions as if\n"
"       PSW W bit is on, i.e. addresses are treated as 64bit. In fact,\n"
"       IDA still will truncate them to 32 bit, but this option changes\n"
"       disassembly of load/store instructions.\n"
"\n"
" Use mnemonic register names\n"
"\n"
"       If checked, IDA will use mnemonic names of the registers:\n"
"         %r26:  %arg0\n"
"         %r25:  %arg1\n"
"         %r24:  %arg2\n"
"         %r23:  %arg3\n"
"         %r28:  %ret0\n"
"\n"
"\n"
"ENDHELP\n"
"HPPA specific options\n"
"\n"
" <~S~implify instructions:C>\n"
" <PSW bit W is on (for 64-bit):C>\n"
" <Use ~m~nemonic register names:C>>\n"
"\n"
"\n";

  if ( keyword == NULL )
  {
    AskUsingForm_c(form, &idpflags);
OK:
    helper.altset(-1, idpflags);
    handle_new_flags();
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT ) return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "HPPA_SIMPLIFY") == 0 )
    {
      setflag(idpflags, IDP_SIMPLIFY, *(int*)value);
      goto OK;
    }
    if ( strcmp(keyword, "HPPA_MNEMONIC") == 0 )
    {
      setflag(idpflags, IDP_MNEMONIC, *(int*)value);
      goto OK;
    }
    if ( strcmp(keyword, "HPPA_PSW_W") == 0 )
    {
      setflag(idpflags,IDP_PSW_W,*(int*)value);
      goto OK;
    }
    return IDPOPT_BADKEY;
  }
}

//-----------------------------------------------------------------------
static const char *shnames[] = { "hppa", NULL };
static const char *lnames[] = {
  "PA-RISC",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_HPPA,                    // id
  PRN_HEX               // hex numbers
  | PR_ALIGN            // data items should be aligned
  | PR_DEFSEG32         // 32-bit segments by default
  | PR_SEGS             // has segment registers
  | PR_SGROTHER         // segment register mean something unknown to the kernel
  | PR_STACK_UP         // stack grows up
  | PR_FULL_HIFXP       // high offsets come with full values
  | PR_TYPEINFO         // type system is supported
  | PR_USE_ARG_TYPES    // use ph.use_arg_types()
  | PR_DELAYED,         // has delayed jumps and calls
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
  intel_data,           // generate ...                    data directive
  NULL,                 // compare operands
  NULL,                 // can_have_type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  DPSEG,                // first
  rVds,                 // last
  8,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  HPPA_null,
  HPPA_last,
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
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  is_sp_based,          // int (*is_sp_based)(op_t &x);
  create_func_frame,    // int (*create_func_frame)(func_t *pfn);
  hppa_get_frame_retsize,// int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,sval_t v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  HPPA_rfi,             // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
  21,                   // high_fixup_bits
};
