
#include "dsp56k.hpp"
#include <diskio.hpp>
#include <entry.hpp>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  // data arithmetic logic unit
  "x", "x0", "x1",
  "y", "y0", "y1",
  // accumulator registers
  "a", "a0", "a1", "a2",
  "b", "b0", "b1", "b2",
  "ab",  // a1:b1
  "ba",  // b1:a1
  "a10", // a1:a0
  "b10", // b1:b0
  // address generation unit (AGU)
  "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",  // pointers
  "n0",  "n1",  "n2",  "n3",  "n4",  "n5",  "n6",  "n7",  // offsets
  "m0",  "m1",  "m2",  "m3",  "m4",  "m5",  "m6",  "m7",  // modifiers
  // Program Control Unit
  "pc",  // Program Counter (16 Bits)
  "mr",  // Mode Register (8 Bits)
  "ccr", // Condition Code Register (8 Bits)
  "sr",  // Status Register (MR:CCR, 16 Bits)
  "omr", // Operating Mode Register (8 Bits)
  "la",  // Hardware Loop Address Register (16 Bits)
  "lc",  // Hardware Loop Counter (16 Bits)
  "sp",  // System Stack Pointer (6 Bits)
  "ss",  // System Stack RAM (15X32 Bits)
  "ssh", // Upper 16 Bits of the Contents of the Current Top of Stack
  "ssl", // Lower 16 Bits of the Contents of the Current Top of Stack
  "sz",  // Stack Size register
  "sc",  // Stack Counter register
  "ep",  // Extension Pointer register
  "vba", // Vector Base Address Register

  "cs","ds",       // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
//6x
static uchar retcode_0[] = { 0x0C, 0x00, 0x00 };
static uchar retcode_1[] = { 0x04, 0x00, 0x00 };
//61
static uchar retcode_2[] = { 0x06, 0x00 };
static uchar retcode_3[] = { 0x07, 0x00 };

static bytes_t retcodes6x[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

static bytes_t retcodes61[] =
{
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Motorola DSP56000 Assembler
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
  "Motorola DSP56K Assembler",
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
  AS2_BYTE1CHAR,// One symbol per processor byte
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
  AS2_BYTE1CHAR,// One symbol per processor byte
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static asm_t *asms[] = { &motasm, &gas, NULL };

//----------------------------------------------------------------------
static ea_t AdditionalSegment(asize_t size, int offset, const char *name)
{
  segment_t s;
  int step = is561xx() ? 0xF : 0x1000000-1;
  s.startEA = freechunk(0x1000000, size, step);
  s.endEA   = s.startEA + size;
  s.sel     = allocate_selector((s.startEA-offset) >> 4);
  s.type    = SEG_DATA;
  s.bitness = ph.dnbits > 16;
  add_segm_ex(&s, name, "DATA", ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.startEA - offset;
}

inline ea_t get_start(segment_t *s)
{  return s ? s->startEA : BADADDR; }

//--------------------------------------------------------------------------
static ioport_t *ports;
static size_t numports;
char device[MAXSTR];
ea_t xmem = BADADDR;
ea_t ymem = BADADDR;
static int xmemsize = 0x10000;
static int ymemsize = 0x10000;

static const char *idaapi dsp56k_callback(const ioport_t *ports, size_t numports, const char *line);

#define callback dsp56k_callback
#include "../iocommon.cpp"

static const char *idaapi dsp56k_callback(const ioport_t *ports, size_t numports, const char *line)
{
  int size;
  if ( sscanf(line, "XMEMSIZE = %i", &size) == 1 )
  {
    xmemsize = size;
RETOK:
    qsnprintf(deviceparams, sizeof(deviceparams), "XMEM=0x%X YMEM=0x%X", xmemsize, ymemsize);
    return NULL;
  }
  if ( !is561xx() && sscanf(line, "YMEMSIZE = %i", &size) == 1 )
  {
    ymemsize = size;
    goto RETOK;
  }
  return standard_callback(ports, numports, line);
}

const char *find_port(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}

//--------------------------------------------------------------------------
static void create_xmem_ymem(void)
{
  if ( xmem == BADADDR )
  {
    xmem = AdditionalSegment(xmemsize, 0, "XMEM");

    if ( !is561xx() )
      ymem = AdditionalSegment(ymemsize, 0, "YMEM");
  }
}

//--------------------------------------------------------------------------
void select_device(const char *dname, int respect_info)
{
  set_device_name(dname, respect_info);

  create_xmem_ymem();

  for ( int i=0; i < numports; i++ )
  {
    ioport_t *p = ports + i;
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

//--------------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
    select_device(device, IORESP_INT);
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
int procnum = -1;
netnode helper;

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
      helper.create("$ dsp56k");
      init_analyzer();
    default:
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:      // new file loaded
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
          select_device(device, IORESP_AREA|IORESP_INT);
        else
          create_xmem_ymem();
      }
      break;

    case processor_t::oldfile:      // old file loaded
      xmem = get_start(get_segm_by_name("XMEM"));
      if ( !is561xx() )
        ymem = get_start(get_segm_by_name("YMEM"));
      {
        char buf[MAXSTR];
        if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
          select_device(buf, IORESP_NONE);
      }
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.supset(0, device);
      break;

    case processor_t::newprc:    // new processor type
      {
        int n = va_arg(va, int);
        if ( procnum == -1 )
        {
          procnum = n;
        }
        else if ( procnum != n )  // can't change the processor type
        {                         // after the initial set up
          warning("Sorry, processor type can not be changed after loading");
          return 0;
        }
        ph.cnbits = (is561xx()             ) ? 16 : 24;
        ph.dnbits = (is561xx() || is566xx()) ? 16 : 24;
        ph.retcodes = (is561xx()           ) ? retcodes61 : retcodes6x;

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
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
// We always return "yes" because of the messy problem that
// there are additional operands with a wrong operand number (always 1)
static bool idaapi can_have_type(op_t &)
{
  return true;
}

//-----------------------------------------------------------------------
static const char *shnames[] =
{
  "dsp56k",
  "dsp561xx",
  "dsp563xx",
  "dsp566xx",
  NULL
};

static const char *lnames[] =
{
  "Motorola DSP 5600x",
  "Motorola DSP 561xx",
  "Motorola DSP 563xx",
  "Motorola DSP 566xx",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_DSP56K,                  // id
  PRN_HEX | PR_ALIGN | PR_BINMEM,
  24,                           // 24 bits in a byte for code segments
  24,                           // 24 bits in a byte for other segments

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
  dsp56k_data,          // generate ...                    data directive
  NULL,                 // compare operands
  can_have_type,        // can_have_type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  vCS,                  // first
  vDS,                  // last
  0,                    // size of a segment register
  vCS, vDS,

  NULL,                 // No known code start sequences
  retcodes6x,

  DSP56_null,
  DSP56_last,
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
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  DSP56_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
