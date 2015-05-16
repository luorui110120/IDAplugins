
#include <ctype.h>
#include "kr1878.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  // data arithmetic logic unit
  "SR0", "SR1", "SR2", "SR3",
  "SR4", "SR5", "SR6", "SR7",
  "DSP", "ISP",
  "a", "b", "c", "d",
  "cs","ds",       // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x0c, 0x00 };
static uchar retcode_1[] = { 0x0d, 0x00 };

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//--------------------------------------------------------------------------
struct interrupt_t
{
  int offset;
  const char *name;
};

static const interrupt_t ints[] =
{
  { 0x0000, "HRESET"                            },  // Hardware RESET
  { 0x0001, "WDOG"                              },
  { 0x0002, "STOVF"                             },
  { 0x0003, "TIMER"                             },
  { 0x0006, "PORTA"                             },
  { 0x0007, "PORTB"                             },
  { 0x000F, "EEPWr"                             },
};

//-----------------------------------------------------------------------
//      Angstrem KR1878VE1 Assembler
//-----------------------------------------------------------------------
static asm_t motasm =
{
//   AS_ASCIIC
   ASH_HEXF4    // $34
  |ASD_DECF0    // 34
  |ASB_BINF2    // %01010
  |ASO_OCTF1    // 0123
  |AS_COLON
  |AS_N2CHR
  |AS_NCMAS
  |AS_ONEDUP,
  0,
  "Angstrem KR1878VE1 Assembler",
  0,
  NULL,         // header lines
  NULL,         // bad instructions
  "org",        // org
  "end",        // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  "dc",         // ascii string directive
  "dcb",        // byte directive
  "dc",         // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  "bs#s(c,) #d, #v", // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "*",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  "global",     // "public" name keyword
  NULL,         // "weak"   name keyword
  "xref",       // "extrn"  name keyword
                // .extern directive requires an explicit object size
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  NULL,         // "align" keyword
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

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static asm_t gas =
{
   AS_ASCIIC
  |ASH_HEXF4    // $34
  |ASD_DECF0    // 34
  |ASB_BINF3    // 0b01010
  |ASO_OCTF1    // 0123
  |AS_COLON
  |AS_N2CHR
  |AS_NCMAS
  |AS_ONEDUP,
  UAS_GNU,
  "GNU-like hypothetical assembler",
  0,
  NULL,         // header lines
  NULL,         // bad instructions
  ".org",       // org
  NULL,         // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
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

static asm_t *asms[] = { &motasm, &gas, NULL };

//----------------------------------------------------------------------
static ea_t AdditionalSegment(int size, int offset, const char *name)
{
  segment_t s;
  s.startEA = freechunk(0x100000, size, 0xF);
  s.endEA   = s.startEA + size;
  s.sel     = allocate_selector((s.startEA-offset) >> 4);
  s.type    = SEG_DATA;
  add_segm_ex(&s, name, "DATA", ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.startEA - offset;
}

inline ea_t get_start(segment_t *s)
{  return s ? s->startEA : BADADDR; }

//--------------------------------------------------------------------------
static ioport_t *xports;
static size_t numxports;
static char device[MAXSTR];
netnode helper;
ea_t xmem;

const char *find_port(ea_t address)
{
  const ioport_t *port = find_ioport(xports, numxports, address);
  return port ? port->name : NULL;
}

static void read_kr1878_cfg(void)
{
  xports = read_ioports(&numxports, "kr1878.cfg", device, sizeof(device), NULL);
  for ( size_t i=0; i < numxports; i++ )
  {
    ioport_t *p = xports + i;
    ea_t ea = xmem + p->address;
    const char *name = p->name;
    ea_t nameea = get_name_ea(BADADDR, name);
    if ( nameea != ea )
    {
      set_name(nameea, "");
      if ( !set_name(ea, name, SN_NOWARN) )
        set_cmt(ea, name, 0);
    }
  }
}

static void set_device_name(const char *dev)
{
  if ( dev )
  {
    qstrncpy(device, dev, sizeof(device));
    read_kr1878_cfg();
  }
}

const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  if ( choose_ioport_device("kr1878.cfg", device, sizeof(device), NULL) )
    read_kr1878_cfg();
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
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
      helper.create("$ kr1878");
      init_analyzer();
      inf.s_assume = 1;
    default:
      break;

    case processor_t::term:
      free_ioports(xports, numxports);
      break;

    case processor_t::newfile:      // new file loaded
      {
        for ( int i=0; i < qnumber(ints); i++ )
        {
          ea_t ea = inf.minEA + ints[i].offset;
          if ( !isLoaded(ea) ) continue;
          add_entry(ea, ea, ints[i].name, true);
        }

        segment_t *s0 = get_first_seg();
        if ( s0 != NULL )
        {
          segment_t *s1 = get_next_seg(s0->startEA);
          set_segm_name(s0, "CODE");
          for ( int i = as; i <= vDS; i++ )
          {
            SetDefaultRegisterValue(s0, i, BADSEL);
            SetDefaultRegisterValue(s1, i, BADSEL);
          }
        }
        xmem = AdditionalSegment(0x100, 0, "MEM");
      }
      read_kr1878_cfg();
      break;

    case processor_t::oldfile:      // old file loaded
      xmem = get_start(get_segm_by_name("MEM"));
      {
        char buf[MAXSTR];
        if ( helper.supval(0, buf, sizeof(buf)) > 0 )
          set_device_name(buf);
      }
      break;

    case processor_t::savebase:
    case processor_t::closebase:
      helper.supset(0, device);
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
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
// We always return "yes" because of the messy problem that
// there are additional operands with wrong operand number (always 1)
static bool idaapi can_have_type(op_t &)
{
  return true;
}

//-----------------------------------------------------------------------
static const char *shnames[] = { "kr1878", NULL };
static const char *lnames[] =
{
  "Angstrem KR1878",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_KR1878,                  // id
  PRN_HEX               // hex numbers
  | PR_ALIGN            // data items must be aligned
  | PR_BINMEM           // segmentation is done by the processor mode
  | PR_SEGS,            // has segment registers
  16,                           // 16 bits in a byte for code segments
  8,                           // 8 bits in a byte for other segments

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
  kr1878_data,          // generate ...                    data directive
  NULL,                 // compare operands
  can_have_type,        // can_have_type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  as,                   // first
  vDS,                  // last
  1,                    // size of a segment register
  vCS, vDS,

  NULL,                 // No known code start sequences
  retcodes,

  KR1878_null,
  KR1878_last,
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
  is_sp_based,          // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,long v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  KR1878_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
