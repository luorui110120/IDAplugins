/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st20.hpp"
#include <fpro.h>
#include <diskio.hpp>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "Areg",       // Evaluation stack register A
  "Breg",       // Evaluation stack register B
  "Creg",       // Evaluation stack register C
  "Iptr",       // Instruction pointer register, pointing to the next instruction to be executed
  "Status",     // Status register
  "Wptr",       // Work space pointer, pointing to the stack of the currently executing process
  "Tdesc",      // Task descriptor
  "IOreg",      // Input and output register
  "cs",  "ds",
};

//--------------------------------------------------------------------------
static uchar ret0[] = { 0x23, 0x22 }; // eret
static uchar ret1[] = { 0x24, 0xF5 }; // altend
static uchar ret2[] = { 0x20, 0xF3 }; // endp
static uchar ret3[] = { 0x61, 0xFF }; // iret
static uchar ret4[] = { 0x68, 0xFD }; // reboot
static uchar ret5[] = { 0x62, 0xFE }; // restart
static uchar ret6[] = { 0x22, 0xF0 }; // ret
static uchar ret7[] = { 0x60, 0xFB }; // tret

static bytes_t retcodes1[] =
{
 { qnumber(ret0), ret0, },
 { 0, NULL }
};

static bytes_t retcodes4[] =
{
 { qnumber(ret1), ret1, },
 { qnumber(ret2), ret2, },
 { qnumber(ret3), ret3, },
 { qnumber(ret4), ret4, },
 { qnumber(ret5), ret5, },
 { qnumber(ret6), ret6, },
 { qnumber(ret7), ret7, },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Hypthetical assembler
//-----------------------------------------------------------------------
static asm_t hypasm =
{
  ASH_HEXF0|    // 1234h
  ASD_DECF0|    // 1234
  ASB_BINF0|    // 1010b
  ASO_OCTF0|    // 1234o
  AS_COLON|     // create colons after data names
  AS_ONEDUP,    // one array definition per line
  0,
  "Hypthetical assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  "org",        // org
  "end",        // end

  ";",          // comment string
  '\"',         // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "dd",         // double words
  "dq",         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  "public",     // "public" name keyword
  NULL,         // "weak"   name keyword
  "extrn",      // "extrn"  name keyword
                // .extern directive requires an explicit object size
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  NULL,         // "align" keyword
  '(', ')',     // lbrace, rbrace
  "mod",        // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "not",        // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
};

static asm_t *asms[] = { &hypasm, NULL };

//--------------------------------------------------------------------------
ea_t memstart;
static ioport_t *ports = NULL;
static size_t numports = 0;
static char device[MAXSTR] = "";
static const char cfgname[] = "st20.cfg";

static void load_symbols(void)
{
  free_ioports(ports, numports);
  ports = read_ioports(&numports, cfgname, device, sizeof(device), NULL);
}

const ioport_t *find_sym(int address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port;
}

//--------------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
    load_symbols();
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
netnode helper;
int procnum;

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
      helper.create("$ st20");
      helper.supval(0, device, sizeof(device));
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:  // new file loaded
    case processor_t::oldfile:  // old file loaded
      load_symbols();
      break;

    case processor_t::savebase:
    case processor_t::closebase:
      helper.supset(0, device);
      break;

    case processor_t::newprc:   // new processor type
      procnum = va_arg(va, int);
      if ( isc4() ) ph.retcodes = retcodes4;
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

//-----------------------------------------------------------------------
static const char *shnames[] = { "st20", "st20c4", NULL };
static const char *lnames[] =
{
  "SGS-Thomson ST20/C1",
  "SGS-Thomson ST20/C2-C4",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_ST20,                    // id
  PRN_HEX|PR_RNAMESOK,
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

  NULL,                 // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  intel_data,           // generate ...                    data directive
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  cs,                   // first
  ds,                   // last
  2,                    // size of a segment register
  cs, ds,

  NULL,                 // No known code start sequences
  retcodes1,

  ST20_null,
  ST20_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  ST20_eret,            // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
